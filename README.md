# Adaptação de regras e corte de pacotes

O foco do TCC é o algoritmo que seleciona regras compatíveis, calcula os
intervalos de payload a preservar e adapta os offsets. O cortador BPF executa
o corte usado nos experimentos com Suricata.

## Começar

Execute na raiz de `tcc`:

```bash
make alg
./build/alg transport-rules/original-tcp-udp.rules build/transport-adapted.rules \
  > build/transport-summary.txt
make test
```

O executável fica em **`build/alg`**. O código e os auxiliares do analisador
ficam em `analisador/`; `make -C analisador` compila somente nessa pasta.
`make clean` remove os diretórios de compilação.

## Organização

| Local | Conteúdo |
|---|---|
| [analisador/](analisador/README.md) | Algoritmo, escopo, geração dos grupos e testes |
| [experiments/](experiments/README.md) | Preparação dos PCAPs e execução dos experimentos |
| [tests/](tests/README.md) | Validação de replay, corte e alertas |
| [Resultados](docs/RESULTADOS_EXPERIMENTOS.md) | Tabelas por carga, método e fontes das medições |
| `application-rules/`, `transport-rules/`, `ip-rules/` | Regras originais, adaptadas e intervalos de cada grupo |
| `af_xdp_kern.c`, `xdp/`, `run_intervals.py` | Cortador BPF e configuração dos intervalos |
| `experiments/pcaps/`, `experiments/results/` | Capturas e resultados locais, fora do Git |

`make rule-groups` regenera os três conjuntos a partir de `suricata.rules`.
Inclui todas as regras aceitas, mesmo as mantidas sem alteração. A base atual
tem 1.535 aceitas: 4 de aplicação, 1.005 de transporte e 526 de rede/IP.
Ao mudar as regras ou os intervalos, regenere os PCAPs e repita as medições.
