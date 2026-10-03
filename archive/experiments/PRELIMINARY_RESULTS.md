# Resultados preliminares — baseline sem cortador

> Registro historico: os resultados de aplicacao abaixo usam o conjunto anterior
> de oito regras e o intervalo `4-183`. Quatro regras dependentes da identificacao
> de HTTP/SMB/SSH foram excluidas do escopo suportado; o cenario `application`
> esta desabilitado. Estes numeros nao validam equivalencia de deteccao nem
> descrevem o conjunto atual. Veja [situacao do conjunto](../../analisador/README.md).

Estes resultados validam a bancada, mas **nao sao os resultados finais da
comparacao**. Eles foram obtidos durante 10 segundos com o primeiro PCAP do
CIC-IDS2017, antes da normalizacao dos quadros agregados. Os ensaios finais
devem usar `CICIDS2017-Monday-mtu1500.pcap`, tanto sem quanto com o cortador.

- `IDS Mbit/s`: throughput bruto processado pelo Suricata.
- `IDS pps`: pacotes por segundo processados pelo Suricata.
- `Perda captura`: `capture.kernel_drops / capture.kernel_packets`, a perda
  reportada pelo proprio Suricata.
- `Deficit total`: diferenca entre pacotes enviados pelo tcpreplay e pacotes
  processados pelo IDS. Inclui a pequena diferenca basal anterior ao socket.

## Regras de aplicacao

| Alvo (Mbit/s) | Ofertado (Mbit/s) | IDS (Mbit/s) | IDS (pps) | Enviados | Processados | Perda captura | Deficit total |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 499,99 | 499,98 | 69.611,18 | 696.222 | 696.112 | 0,000000% | 0,015800% |
| 1.000 | 999,99 | 999,99 | 132.143,80 | 1.321.618 | 1.321.438 | 0,000000% | 0,013620% |
| 2.000 | 1.999,99 | 1.999,98 | 264.107,30 | 2.641.432 | 2.641.073 | 0,000000% | 0,013591% |
| 5.000 | 4.991,91 | 4.991,88 | 654.370,85 | 6.546.897 | 6.545.999 | 0,000000% | 0,013716% |
| 10.000 | 9.978,20 | 9.978,14 | 1.307.220,15 | 13.087.496 | 13.085.710 | 0,000000% | 0,013647% |

## Regras de transporte

| Alvo (Mbit/s) | Ofertado (Mbit/s) | IDS (Mbit/s) | IDS (pps) | Enviados | Processados | Perda captura | Deficit total |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 499,99 | 499,98 | 69.611,20 | 696.222 | 696.112 | 0,000000% | 0,015800% |
| 1.000 | 999,99 | 999,99 | 132.144,00 | 1.321.618 | 1.321.440 | 0,000000% | 0,013468% |
| 2.000 | 1.999,99 | 1.999,98 | 264.107,20 | 2.641.432 | 2.641.072 | 0,000000% | 0,013629% |
| 5.000 | 4.992,06 | 4.992,04 | 654.404,52 | 6.547.557 | 6.546.663 | 0,000000% | 0,013654% |
| 10.000 | 9.979,40 | 9.568,26 | 1.268.608,46 | 13.083.714 | 12.697.501 | 2,938611% | 2,951861% |

## Regras IP/rede

| Alvo (Mbit/s) | Ofertado (Mbit/s) | IDS (Mbit/s) | IDS (pps) | Enviados | Processados | Perda captura | Deficit total |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 500 | 499,99 | 499,98 | 69.611,28 | 696.222 | 696.113 | 0,000000% | 0,015656% |
| 1.000 | 999,99 | 999,99 | 132.143,80 | 1.321.618 | 1.321.438 | 0,000000% | 0,013620% |
| 2.000 | 1.999,99 | 1.999,98 | 264.107,30 | 2.641.432 | 2.641.073 | 0,000000% | 0,013591% |
| 5.000 | 4.992,79 | 4.992,11 | 654.522,94 | 6.550.672 | 6.549.158 | 0,009405% | 0,023112% |
| 10.000 | 9.980,74 | 7.876,78 | 1.107.741,87 | 13.086.224 | 11.084.804 | 15,282588% | 15,294099% |

## Arquivos brutos consolidados

- Aplicacao: `results/sweep_baseline_application_20260926T021736Z/summary.tsv`
  (os pontos corrigidos de 5 e 10 Gbit/s estao nos diretorios `g2` e `g3`).
- Transporte: `results/sweep_baseline_transport_20260926T022402Z/summary.tsv`.
- IP/rede: `results/sweep_baseline_ip_20260926T195909Z/summary.tsv`.

Cada diretorio individual tambem contem `stats.log`, `tcpreplay-*.log`,
`interface-counters.tsv` e o `summary.tsv` daquela execucao.
