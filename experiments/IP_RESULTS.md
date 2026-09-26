# Comparacao a 5 Gbit/s — regras de rede/IP

Ensaio de 10 segundos com o PCAP normalizado
`CICIDS2017-Monday-mtu1500.pcap`, dois geradores e intervalo `21-36`.
Baseline e cortador carregaram as mesmas 45 regras e criaram oito workers.

| Modo | Trafego real | IDS | IDS (pps) | Perda de captura | Deficit total | ENOBUFS |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 4.998,58 Mbit/s | 4.499,71 Mbit/s | 843.791,40 | 7,711808% | 7,724262% | 0 |
| Cortador | 4.999,99 Mbit/s | 423,31 Mbit/s | 792.916,80 | 13,295217% | 13,306830% | 2.978.950 |

## Separacao entre corte e perda

A coluna `ids_byte_reduction_percent` do resumo bruto compara todos os bytes
enviados com os bytes decodificados. Portanto, ela mistura bytes removidos pelo
cortador com pacotes perdidos antes da decodificacao. Neste ensaio ela informou
91,53%, mas esse valor nao deve ser apresentado sozinho como reducao do corte.

Usando o tamanho medio apenas dos pacotes efetivamente decodificados:

- trafego enviado no modo cutter: 683,34 bytes/pacote;
- trafego decodificado depois do corte: 66,73 bytes/pacote;
- reducao estimada do tamanho medio: 90,23%.

## Leitura

- Os dois modos atingiram os 5 Gbit/s externos, mas o cortador apresentou perda
  de captura 5,58 pontos percentuais maior.
- Das 45 regras, 41 sao de eventos do decodificador e apenas uma inspeciona
  payload. Assim, remover payload reduz pouco do trabalho dominante dessas
  regras, que continua sendo executado por pacote.
- Alguns contadores internos do Suricata, como `tcp.overlap`, tambem variaram
  entre as execucoes. Eles nao permitem atribuir a perda a uma causa especifica
  e nao alteram o fato de que os intervalos usados pelo cortador sao definidos
  sobre cada pacote.

## Conclusao provisoria

No conjunto de rede/IP, a grande reducao do tamanho dos pacotes nao produziu
ganho de capacidade do IDS. O throughput externo foi mantido, mas a perda de
captura aumentou. O resultado e coerente com um conjunto dominado por regras de
decoder/header e com o custo adicional do processamento XDP por pacote. O
experimento atual nao isola qual componente causou o aumento da perda.

## Dados brutos

- Baseline: `results/baseline_ip_5000mbps_g2_20260926T213822Z/summary.tsv`
- Cortador: `results/cutter_ip_5000mbps_g2_20260926T213900Z/summary.tsv`
