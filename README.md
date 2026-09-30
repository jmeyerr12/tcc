# Adaptação de regras e corte de pacotes para o Suricata

O foco do projeto e o algoritmo que adapta o conjunto de regras: calcula os
intervalos a conservar e reajusta os offsets para o Suricata. O cortador XDP
executa a compactacao do payload de cada pacote conforme esses intervalos.

O objetivo e comparar **sem e com cortador**, usando um PCAP generico de
Internet, os grupos de regras **aplicacao, transporte e rede/IP** e as taxas
de **500 Mb/s, 1, 2, 5 e 10 Gb/s**.

## Compilar e verificar

```bash
make
make test
```

Executaveis e objetos ficam em `build/`. Para adaptar um conjunto:

```bash
./build/alg transport-rules/original-tcp-udp.rules build/transport-adapted.rules \
  > build/transport-summary.txt
```

## Onde encontrar

- [Proximos passos](PROXIMOS_PASSOS.md): plano da rodada experimental.
- [Resumo para a reuniao](docs/REUNIAO_PROFESSOR.md): resultados e decisoes.
- [Experimentos](experiments/SETUP_POPOS.md): ambiente e comandos de execucao.
- [Testes](tests/README.md): verificacao de intervalos e teste com o Suricata.
- [Escopo](docs/escopo-algoritmo.md): regras aceitas e limites atuais.
- [Problemas do corte](docs/LIMITACOES_DO_CORTE.md): efeitos sobre a deteccao,
  limites do executor e implicacoes para o adaptador.
- `application-rules/`, `transport-rules/`, `ip-rules/`: regras e summaries.
- `experiments/pcaps/` e `experiments/results/`: capturas e resultados locais.
- `archive/`: relatorios, rascunhos e artefatos antigos, apenas para consulta.

**Etapa atual:** fechar as condicoes de uso do adaptador e realizar os
experimentos com os tres grupos, aproveitando os pilotos existentes.
Aplicacao continua no objetivo; seu cenario atual esta bloqueado nos scripts
enquanto o conjunto e suas dependencias precisam ser revistos. O escopo
implementado e as limitacoes conhecidas delimitam as conclusoes.
