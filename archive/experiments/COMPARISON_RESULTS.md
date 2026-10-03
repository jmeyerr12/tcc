# Comparacao controlada — regras de aplicacao

> Registro historico: os resultados de aplicacao abaixo usam o conjunto anterior
> de oito regras e o intervalo `4-183`. Quatro regras dependentes da identificacao
> de HTTP/SMB/SSH foram excluidas do escopo suportado; o cenario `application`
> esta desabilitado. Estes numeros nao validam equivalencia de deteccao nem
> descrevem o conjunto atual. Veja [situacao do conjunto](../../analisador/README.md).

Resultados de uma repeticao de 10 segundos com o mesmo arquivo
`CICIDS2017-Monday-mtu1500.pcap` nos quatro casos:

- baseline: XDP desligado e regras originais;
- cortador anterior: copia de um byte por callback e checksum de uma palavra
  de 16 bits por callback;
- primeira otimizacao: copia e checksum em blocos de 64 bytes;
- segunda otimizacao: blocos de 256 bytes, `bpf_csum_diff` e caminho rapido
  para um unico intervalo.

Todos os cortadores usaram o intervalo `4-183` e as mesmas regras adaptadas.
Antes da medicao, a segunda otimizacao passou no teste `BPF_PROG_TEST_RUN`:
dois pacotes foram reduzidos de 484 para 258 bytes, com payload, comprimentos,
headers e checksums verificados.

| Alvo | Baseline | Cortador anterior | Otimizacao 1 | Otimizacao 2 | Alvo atingido (v2) | IDS v2 | IDS v2 (pps) | Perda v2 | Reducao de bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 Mbit/s | 499,99 | 499,99 | 499,99 | 499,99 | 100,00% | 110,94 | 94.800,68 | 0,000000% | 77,81% |
| 1 Gbit/s | 1.000,00 | 999,99 | 1.000,00 | 1.000,00 | 100,00% | 217,09 | 184.105,70 | 0,000000% | 78,29% |
| 2 Gbit/s | 2.000,00 | 1.123,89 | 1.996,52 | 1.998,08 | 99,90% | 433,70 | 367.787,21 | 0,000000% | 78,29% |
| 5 Gbit/s | 5.000,00 | 1.449,05 | 4.612,31 | 4.993,49 | 99,87% | 1.079,03 | 913.562,88 | 0,000000% | 78,39% |
| 10 Gbit/s | 8.363,79 | 1.501,51 | 3.432,33 | 3.748,35 | 37,48% | 807,82 | 683.341,57 | 0,025756% | 78,45% |

Os valores de throughput estao em Mbit/s. `IDS v2` e a taxa em bytes que
chegou ao Suricata depois do corte; ela nao deve ser comparada diretamente com
o trafego externo sem considerar a reducao de aproximadamente 78%. A perda de
captura e `capture.kernel_drops / capture.kernel_packets`.

## Efeito das otimizacoes

- Em 2 Gbit/s, o throughput externo passou de 1.123,89 para 1.998,08 Mbit/s,
  ganho de 77,8%, e o alvo passou a ser praticamente atingido.
- Em 5 Gbit/s, a segunda otimizacao passou de 4.612,31 para 4.993,49 Mbit/s,
  ganho adicional de 8,26%, e atingiu 99,87% do alvo. Em relacao ao cortador
  anterior, o resultado e 3,45 vezes maior.
- Nesse ponto, o Suricata recebeu somente 1.079,03 Mbit/s, mas processou
  913.562,88 pacotes/s sem perda de captura reportada.
- O maior throughput observado com o cortador subiu de 1.501,51 para
  4.993,49 Mbit/s, aproximadamente 3,33 vezes.
- No ponto nominal de 10 Gbit/s, a segunda otimizacao melhorou o resultado da
  primeira em 9,21%, de 3.432,33 para 3.748,35 Mbit/s.
- A hipotese de que os callbacks por byte/palavra eram o principal gargalo da
  versao anterior foi confirmada pelos dois experimentos.

## Interpretacao do ponto nominal de 10 Gbit/s

O resultado de 3.748,35 Mbit/s nao representa uma capacidade menor que a
observada em 5 Gbit/s. Com quatro geradores concorrentes, o `tcpreplay`
registrou 24.914.658 repeticoes por `ENOBUFS`, exatamente o mesmo aumento de
`tx_dropped` na interface. A bancada entrou em contrapressao antes de entregar
10 Gbit/s ao IDS, e a concorrencia excessiva reduziu o throughput util.

O ponto de saturacao deve ser refinado com taxas intermediarias e com numero
fixo de geradores. Os dados atuais sustentam que a implementacao processa pelo
menos 4,99 Gbit/s de trafego original, mas nao sustentam que 3,75 Gbit/s seja
seu teto.

Um controle adicional no alvo de 10 Gbit/s, usando tres geradores nos dois
modos, confirmou o efeito da concorrencia:

| Modo (3 geradores) | Trafego real | IDS | IDS (pps) | ENOBUFS | Perda de captura |
|---|---:|---:|---:|---:|---:|
| Baseline | 7.712,94 Mbit/s | 7.699,30 Mbit/s | 1.404.587,19 | 0 | 0,133147% |
| Cortador v2 | 4.430,88 Mbit/s | 955,14 Mbit/s | 807.975,68 | 18.524.932 | 0,000000% |

O cortador com tres geradores foi 18,21% mais rapido que com quatro no mesmo
alvo nominal. Entretanto, a contrapressao (`ENOBUFS`) continua ocorrendo antes
do IDS e impede uma comparacao de perda sob a mesma carga efetivamente
entregue.

## Conclusao provisoria

A segunda otimizacao resolveu a regressao do cortador ate 5 Gbit/s. Nesse
ponto, baseline e cortador atingiram praticamente a mesma carga e taxa de
pacotes, enquanto o cortador entregou ao Suricata 78,39% menos bytes. Ate
2 Gbit/s, os dois modos tambem atingiram os alvos sem perda de captura.

Ainda nao e correto afirmar ganho final de capacidade do IDS sobre o baseline:
esta bancada mede em conjunto geracao, veth, XDP e Suricata. Para uma conclusao
final, faltam repeticoes e um ensaio que leve o Suricata, e nao os geradores ou
o caminho XDP, ao limite.

## Dados brutos

- Baseline: `results/sweep_baseline_application_20260926T204355Z/summary.tsv`
- Cortador anterior: `results/sweep_cutter_application_20260926T203653Z/summary.tsv`
- Primeira otimizacao: `results/sweep_cutter_application_20260926T210241Z/summary.tsv`
- Segunda otimizacao: `results/sweep_cutter_application_20260926T211703Z/summary.tsv`
- Controle a 10 Gbit/s com tres geradores:
  `results/cutter_application_10000mbps_g3_20260926T212122Z/summary.tsv` e
  `results/baseline_application_10000mbps_g3_20260926T212204Z/summary.tsv`
