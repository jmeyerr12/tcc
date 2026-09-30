# Comparacao a 5 Gbit/s — regras de transporte

Ensaio de 10 segundos com o PCAP normalizado
`CICIDS2017-Monday-mtu1500.pcap`, dois geradores e intervalos `0-313` e
`500-1363`.

Antes da medicao final, o caminho rapido para dois intervalos passou no teste
`BPF_PROG_TEST_RUN`, que verificou payload, comprimentos, headers e checksums.

| Modo | Trafego real | Alvo atingido | IDS | IDS (pps) | Reducao de bytes | Perda de captura | Deficit total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 4.999,99 Mbit/s | 100,00% | 4.978,05 Mbit/s | 911.453,10 | 0,44% | 0,333340% | 0,346700% |
| Cortador antes do caminho rapido | 4.366,06 Mbit/s | 87,32% | 3.589,16 Mbit/s | 791.685,58 | 17,79% | 0,561263% | 0,574469% |
| Cortador com caminho rapido | 4.980,31 Mbit/s | 99,61% | 4.052,85 Mbit/s | 899.132,07 | 18,62% | 1,351740% | 1,364993% |

## Leitura

- O caminho rapido eliminou quatro callbacks por pacote e elevou o throughput
  do cortador em 14,07%, fazendo-o atingir praticamente os 5 Gbit/s.
- Os intervalos de transporte preservam ate 1.178 bytes de payload. Por isso,
  a reducao media de bytes foi apenas 18,62%, muito menor que os 78,39% das
  regras de aplicacao.
- A perda de captura do cortador ficou 1,0184 ponto percentual acima do
  baseline. Portanto, neste conjunto o ganho de reducao de bytes nao se
  converteu em menor perda na carga de 5 Gbit/s.
- O cortador sofreu 2.300.938 repeticoes por `ENOBUFS`; o baseline nao teve
  `ENOBUFS`. A bancada continua dividindo CPU entre geradores, XDP e Suricata.

## Conclusao provisoria

Para transporte, o cortador otimizado recupera o throughput externo de
5 Gbit/s, mas nao supera o baseline: reduz somente 18,62% dos bytes e apresenta
mais perda de captura. Esse resultado deve ser apresentado separadamente do
caso de aplicacao, no qual a reducao de bytes e muito maior.

## Dados brutos

- Baseline: `results/baseline_transport_5000mbps_g2_20260926T213123Z/summary.tsv`
- Cortador antes do caminho rapido:
  `results/cutter_transport_5000mbps_g2_20260926T213232Z/summary.tsv`
- Cortador com caminho rapido:
  `results/cutter_transport_5000mbps_g2_20260926T213547Z/summary.tsv`
