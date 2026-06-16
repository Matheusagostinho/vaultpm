# Vault — Secure Package Manager (CLAUDE.md)

> Você é um Staff Engineer Rust especialista em tooling, segurança de supply chain e sistemas de baixo nível.
> Seu objetivo é implementar o **Vault**, um gerenciador de pacotes Node.js open source escrito em Rust,
> inspirado no pnpm porém com uma camada de segurança ativa contra ataques de supply chain.
> Trabalhe de forma **iterativa, incremental e orientada a testes**. Nunca assuma — pergunte quando houver ambiguidade.

---

## 1. Visão do Produto

**Vault** é um gerenciador de pacotes Node.js que combina a eficiência do pnpm (hard links + content-addressable store)
com verificação ativa de segurança antes de qualquer instalação, protegendo contra ataques de supply chain como
`event-stream`, `ua-parser-js` e `node-ipc`.

**CLI principal:**
```bash
vault install        # instala dependências
vault install lodash # adiciona pacote
vt install           # alias curto
vt install lodash
vt add lodash
vt remove lodash
vt run dev
vt audit             # auditoria manual
```

---

## 2. Problema

Ataques de supply chain em pacotes npm cresceram exponencialmente:
- Maintainer takeover (sequestro de conta de mantenedor)
- Pacotes maliciosos com `postinstall` fazendo exfiltração de dados
- Dependências transitivas com CVEs conhecidos instaladas silenciosamente
- Nenhum gerenciador atual verifica ativamente ANTES de instalar

---

## 3. Solução — Diferenciais do Vault

1. **Pre-install audit obrigatório** — verifica integridade, CVEs e comportamento antes de extrair qualquer arquivo
2. **Análise estática de lifecycle scripts** — escaneia `preinstall`/`postinstall` em busca de padrões maliciosos
3. **Sandbox de execução** — lifecycle scripts rodam isolados via `landlock` (Linux) sem acesso a rede/fs externo
4. **Verificação de proveniência** — suporte a Sigstore attestations
5. **Detecção de maintainer takeover** — alerta quando mantenedor mudou recentemente
6. **Content-Addressable Store com metadados de segurança** — store global igual ao pnpm, mas com audit cache

---

## 4. Arquitetura

```
vault/
├── crates/
│   ├── cli/              # Ponto de entrada, parsing de args (clap)
│   ├── core/             # Orquestrador principal
│   │   ├── resolver/     # SAT solver de dependências (pubgrub)
│   │   ├── fetcher/      # Download paralelo de tarballs
│   │   └── linker/       # Hard links + symlinks no node_modules
│   ├── store/            # Content-Addressable Store global (~/.vault/store)
│   ├── audit/            # Camada de segurança (DIFERENCIAL)
│   │   ├── integrity.rs  # SHA-512 + verificação do registry
│   │   ├── osv.rs        # CVE lookup via OSV.dev API
│   │   ├── npm_audit.rs  # npm audit API
│   │   ├── maintainer.rs # Detecção de takeover via npm registry API
│   │   ├── static_scan.rs# Análise estática de postinstall scripts
│   │   └── provenance.rs # Sigstore attestation (fase 3)
│   ├── sandbox/          # Execução isolada de lifecycle scripts
│   │   ├── landlock.rs   # Linux Landlock LSM
│   │   └── policy.rs     # Políticas de permissão configuráveis
│   └── config/           # vault.toml + vault.lock parsing
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/         # Pacotes de teste (legítimos e maliciosos simulados)
├── vault.toml            # Config do projeto (análogo ao .npmrc)
└── AGENTS.md             # Instruções para agentes de IA neste repo
```

---

## 5. Stack

| Componente | Tecnologia | Justificativa |
|---|---|---|
| Linguagem | Rust (stable) | Performance, segurança de memória, sem GC |
| Async runtime | Tokio | Downloads paralelos, I/O não-bloqueante |
| HTTP client | reqwest | Async, suporte a TLS, streaming |
| SAT resolver | pubgrub crate | Mesmo algoritmo do Cargo/Dart pub |
| CLI parsing | clap v4 (derive) | Ergonomia, autocomplete, subcomandos |
| Serialização | serde + serde_json | JSON do registry npm |
| Hash | sha2 | SHA-512 para integridade |
| AST JS (scan) | swc_core | Parse de scripts postinstall para análise |
| Sandbox | landlock-rs | Isolamento via Linux Landlock LSM |
| Sigstore | sigstore-rs | Verificação de proveniência (fase 3) |
| Testes | cargo test + nextest | Unitários e integração |

---

## 6. Fluxo Principal — `vault install`

```
1. Ler package.json do projeto
        │
        ▼
2. SAT resolver → grafo de dependências completo
        │
        ▼
3. Verificar vault.lock (versões já fixadas?)
        │
        ▼
4. Para cada pacote a instalar (paralelo, N workers):
        │
        ├─ 4a. Buscar metadados no registry (npm.registry.com)
        │       ├── Maintainer mudou nos últimos 30 dias? → WARN
        │       └── Pacote tem downloads < threshold? → WARN
        │
        ├─ 4b. Baixar tarball (se não estiver no store)
        │
        ├─ 4c. Verificar integridade
        │       ├── SHA-512 bate com registry? → ABORT se não
        │       └── Hash já auditado no store? → skip próximos passos
        │
        ├─ 4d. Consultar CVEs (OSV.dev API)
        │       └── Vulnerabilidade crítica? → ABORT (configurável)
        │
        ├─ 4e. Análise estática do pacote
        │       ├── Tem postinstall/preinstall script?
        │       │   └── SIM → escanear:
        │       │       ├── curl/wget/fetch para domínio externo? → BLOCK
        │       │       ├── Acesso a ~/.ssh, ~/.aws, $HOME? → BLOCK
        │       │       ├── eval(base64_decode(...))? → BLOCK
        │       │       ├── process.env com exfiltração? → BLOCK
        │       │       └── Padrão suspeito? → WARN + prompt usuário
        │       └── NÃO → seguro, prosseguir
        │
        ├─ 4f. Marcar hash como auditado no store
        │
        └─ 4g. Criar hard links no node_modules do projeto
                └── Symlinks para .vault/node_modules/<pkg>
        │
        ▼
5. Executar lifecycle scripts aprovados (em sandbox)
        │
        ▼
6. Atualizar vault.lock
        │
        ▼
7. Exibir relatório: X pacotes instalados, Y avisos, Z bloqueados
```

---

## 7. Content-Addressable Store

```
~/.vault/
├── store/
│   └── v1/
│       └── files/
│           ├── ab/cdef1234...   ← arquivo individual (hard link source)
│           └── ff/a1b2c3...
├── packages/
│   └── lodash@4.17.21/
│       ├── audit.json           ← resultado do audit cacheado
│       └── files → ../store/v1/files/...
└── config.toml
```

Cada arquivo de cada pacote é armazenado **uma única vez** por hash de conteúdo.
10 projetos usando `lodash@4.17.21` = 1 cópia no disco.

---

## 8. Análise Estática (`static_scan.rs`)

Padrões maliciosos a detectar nos scripts `preinstall`/`postinstall`/`install`:

```rust
// Padrões a bloquear (regex + AST)
const BLOCK_PATTERNS: &[&str] = &[
    r"curl\s+https?://",           // download externo
    r"wget\s+https?://",
    r"fetch\s*\(\s*['\"]https?://", // JS fetch externo
    r"eval\s*\(",                   // eval genérico
    r"Buffer\.from\(.+,\s*['\"]base64['\"]\)", // decode base64
    r"\$HOME|~\/\.ssh|~\/\.aws",   // acesso a credenciais
    r"process\.env\..*(KEY|SECRET|TOKEN|PASSWORD)", // exfiltração de env
    r"require\s*\(\s*['\"]child_process['\"]\)", // exec de processos
];

// Padrões a avisar (warn, pede confirmação)
const WARN_PATTERNS: &[&str] = &[
    r"require\s*\(\s*['\"]fs['\"]\)",   // acesso ao filesystem
    r"require\s*\(\s*['\"]net['\"]\)",  // socket de rede
    r"process\.env",                     // qualquer env var
];
```

---

## 9. Sandbox (`sandbox/landlock.rs`)

Quando um lifecycle script é aprovado pela análise estática, roda com:

```
Permissões concedidas:
  ├── FS read:  ./node_modules, ~/.vault/store
  ├── FS write: ./node_modules/<pkg_name>
  └── FS exec:  /usr/bin/node, /usr/bin/sh

Permissões bloqueadas:
  ├── FS: ~/.ssh, ~/.aws, ~/.config, /etc
  ├── Network: qualquer socket externo
  └── Exec: curl, wget, python, bash (fora da whitelist)
```

Implementado via Linux Landlock LSM (kernel 5.13+).
Fallback para modo sem sandbox com aviso explícito em sistemas mais antigos.

---

## 10. Configuração — `vault.toml`

```toml
[security]
block_postinstall_network = true       # bloqueia rede em postinstall
warn_new_maintainer_days = 30          # avisa se maintainer mudou recentemente
min_weekly_downloads = 100             # avisa pacotes com poucos downloads
abort_on_critical_cve = true           # aborta se CVE crítico encontrado
require_provenance = false             # exige Sigstore (modo strict)

[audit]
sources = ["osv", "npm"]              # fontes de CVE (osv = gratuito)
cache_ttl_hours = 24                   # cache de audit por 24h

[sandbox]
enabled = true                         # sandbox para lifecycle scripts
allow_fs_read = ["./node_modules"]
allow_fs_write = ["./node_modules"]
allow_net = []                         # vazio = sem rede

[store]
path = "~/.vault/store"               # store global
```

---

## 11. `vault.lock`

Formato JSON (versionado no git):

```json
{
  "lockfileVersion": 1,
  "packages": {
    "lodash@4.17.21": {
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-...",
      "auditedAt": "2026-06-16T00:00:00Z",
      "auditSources": ["osv", "npm"],
      "cveStatus": "clean",
      "maintainerVerified": true,
      "sandboxed": false
    }
  }
}
```

---

## 12. Plano de Implementação — Fases

### Fase 1 — MVP Funcional (core sem segurança)
- [ ] CLI básica com `clap`: `vault install`, `vault add <pkg>`, `vault remove <pkg>`
- [ ] Alias `vt` funcionando
- [ ] Fetch de metadados do npm registry
- [ ] SAT resolver com `pubgrub`
- [ ] Download paralelo de tarballs com `tokio` + `reqwest`
- [ ] Verificação SHA-512
- [ ] CAS store em `~/.vault/store`
- [ ] Hard links + symlinks no `node_modules`
- [ ] Geração do `vault.lock`

### Fase 2 — Camada de Segurança
- [ ] Integração OSV.dev API (gratuita)
- [ ] Integração npm audit API
- [ ] Detecção de maintainer recente via registry API
- [ ] Análise estática de lifecycle scripts (regex + swc AST)
- [ ] Cache de audit no store (`audit.json` por hash)
- [ ] Relatório de segurança no terminal com cores
- [ ] Configuração via `vault.toml`

### Fase 3 — Sandbox + Proveniência
- [ ] Sandbox via `landlock-rs` para lifecycle scripts
- [ ] Fallback gracioso em kernels sem Landlock
- [ ] Suporte a Sigstore attestations
- [ ] Modo `--strict` (exige proveniência)

### Fase 4 — Polimento
- [ ] `vt audit` — auditoria standalone
- [ ] `vt why <pkg>` — por que esse pacote foi instalado
- [ ] `vt licenses` — relatório de licenças
- [ ] Output colorido e progress bars (indicatif)
- [ ] Autocomplete shell (zsh/bash/fish)
- [ ] CI/CD: GitHub Actions com cargo test + nextest

---

## 13. Testes

### Unitários (`crates/*/src/`)
- Resolver: testar conflitos de versão, ranges semver
- Integrity: SHA-512 de fixtures conhecidas
- Static scan: detectar cada padrão malicioso isoladamente
- Config parser: vault.toml válidos e inválidos

### Integração (`tests/integration/`)
- `vault install` em projeto fixture → verifica estrutura do node_modules
- Pacote com CVE → deve abortar (modo strict)
- Pacote com postinstall suspeito → deve bloquear
- Pacote limpo → deve instalar normalmente
- Alias `vt` → mesmo comportamento que `vault`

### Fixtures (`tests/fixtures/`)
- `clean-package/` — pacote legítimo sem scripts
- `postinstall-network/` — simula exfiltração via curl
- `postinstall-env/` — simula acesso a process.env
- `known-cve-package/` — pacote com CVE conhecido no OSV

---

## 14. Padrões de Código

- **Errors**: usar `thiserror` para tipos de erro, `anyhow` no CLI
- **Async**: tudo async/await com Tokio, sem `std::thread::spawn` desnecessário
- **Logging**: `tracing` crate (não `println!`)
- **Testes**: todo módulo com `#[cfg(test)]` no final do arquivo
- **Clippy**: `#![deny(clippy::all)]` no lib.rs de cada crate
- **Docs**: `///` em toda função pública
- **Commits**: Conventional Commits (`feat:`, `fix:`, `security:`, `test:`)

---

## 15. Referências

- pnpm source: https://github.com/pnpm/pnpm
- pubgrub crate: https://github.com/nickel-lang/pubgrub
- OSV.dev API: https://api.osv.dev/v1/query (sem auth, gratuita)
- landlock-rs: https://github.com/landlock-lsm/rust-landlock
- sigstore-rs: https://github.com/sigstore/sigstore-rs
- swc (JS AST): https://github.com/swc-project/swc
- npm registry API: https://registry.npmjs.org/<pkg>
- Socket.dev (referência de mercado): https://socket.dev

---

## Instrução Final para o Agente

Comece sempre pela **Fase 1**. Não implemente segurança antes de ter o core funcionando.

A cada feature implementada:
1. Escreva os testes primeiro (TDD quando possível)
2. Implemente
3. Rode `cargo test` e `cargo clippy`
4. Só então avance

Se encontrar decisão arquitetural não coberta aqui, **pergunte antes de assumir**.

O projeto deve compilar e passar em todos os testes a cada commit.
