# Experimentos

Execute os comandos na raiz de `tcc`. O fluxo atual compara PCAP original com
regras originais e PCAP previamente cortado com regras adaptadas. O XDP fica
desligado durante a medição. As [tabelas de resultados](../docs/RESULTADOS_EXPERIMENTOS.md)
registram as configurações e as fontes de cada rodada.

## Preparar

São necessários Linux com suporte a BPF, Make, g++, clang, Python 3,
libbpf/libelf/zlib (bibliotecas e headers), Suricata, tcpreplay, tcpdump,
iproute2, ethtool e bpftool. A rodada registrada usou Suricata 8.0.7 e
tcpreplay 4.3.4. A preparação do corte usa `BPF_PROG_TEST_RUN` e exige root.

Coloque `CICIDS2017-Monday-mtu1500.pcap` em `experiments/pcaps/`.
Esse arquivo local deriva de uma amostra de segunda-feira do CICIDS2017,
com tráfego benigno. Na preparação anterior, 48.014 segmentos TCP foram
encurtados para MTU 1500, sem resegmentação; portanto, não é o PCAP bruto.
SHA-256 dessa entrada:

```text
a652a6dfafa1312f3f9d7fcb01cf4ec045826d1a91a4b38da346be4df66225d6
```

```bash
make precut-tools
sudo ./experiments/prepare_pre_cut_pcaps.sh
```

O script filtra IPv4 sem opções, TCP/UDP não fragmentado e gera uma base
comum e três versões cortadas. Os quatro PCAPs atuais têm 265.848 pacotes.
O executor aceita PCAP clássico little-endian, Ethernet, checksums válidos na
entrada e payload de até 2048 bytes. Os PCAPs não são versionados no Git.

## Executar

Exemplo de uma comparação, por 10 segundos e carga equivalente de 500 Mbit/s:

```bash
sudo ./experiments/run_pre_cut_comparison.sh application 10 500
```

Grupos: `application`, `transport`, `ip`. Cargas: `500`, `1000`, `2000`, `5000`,
`7500`; omitir a carga ou usar `all` executa todas. O script prepara as interfaces,
desliga o XDP e grava logs e `comparison.tsv` em `experiments/results/`.
Até 5 Gbit/s, ajusta a taxa do PCAP cortado pela proporção de bytes; em 7,5 Gbit/s,
usam-se alvos de PPS e exige-se pelo menos 99% do alvo em ambos os modos.
Os comandos com afinidade de CPU usados na bancada estão nos
[resultados](../docs/RESULTADOS_EXPERIMENTOS.md#reproducao).

## Arquivos para compartilhar

Caminhos relativos à raiz de `tcc`:

| Grupo | Regras originais | Regras adaptadas |
|---|---|---|
| Aplicação | `application-rules/original-application.rules` | `application-rules/original-application-adapted.rules` |
| Transporte | `transport-rules/original-tcp-udp.rules` | `transport-rules/original-tcp-udp-adapted.rules` |
| Rede/IP | `ip-rules/original-ip.rules` | `ip-rules/original-ip-adapted.rules` |

Em `experiments/pcaps/`, os três cortados são:

- `CICIDS2017-Monday-supported-application-cut.pcap`
- `CICIDS2017-Monday-supported-transport-cut.pcap`
- `CICIDS2017-Monday-supported-ip-cut.pcap`

O baseline é `CICIDS2017-Monday-supported.pcap`, com SHA-256:

```text
8e7aa1a4051b2fc3cd6d92dc56821b8643cfda6b8e1c996430e5fa6938838cf5
```

Há **um cortador BPF com três configurações**. Compartilhe `af_xdp_kern.c`,
`xdp/parsing_helpers.h`, `run_intervals.py`, os `summary.txt` de cada grupo e,
se necessário, `build/af_xdp_kern.o`, gerado por `make bpf`.
`tests/wash_pcap.cpp` é o executor usado para cortar os PCAPs.

| Grupo | Intervalos de entrada (Merged, inclusivos) | Após compactação |
|---|---|---|
| Aplicação | `4-183` | `0-179` |
| Transporte | `0-313`, `500-1363` | `0-313`, `314-1177` |
| Rede/IP | `(nenhum)`; executor conserva `0-0` | `0-0` |

Use os intervalos **Merged**, não os Adjusted, para configurar o cortador.

## Condições de interpretação

O cortador atualiza comprimentos IP/UDP, mas **não recalcula checksums** nem
reajusta seq/ACK TCP. O Suricata foi executado com `-k none`. VLAN, fragmentos,
extensões IPv6, protocolos e tamanhos não suportados passam sem corte; os
PCAPs destes experimentos foram restringidos ao subconjunto suportado.

O PCAP benigno e a perda de captura não demonstram preservação de detecção.
Há uma comparação por ponto, sem repetições suficientes para intervalos de
confiança. As medições com PCAP previamente cortado não incluem o custo do XDP.
Para detecção, há [casos sintéticos positivos e negativos](../tests/README.md).
As regras foram usadas no Suricata; o carregamento e o tratamento de checksums
no Snort ainda precisam ser validados, incluindo sintaxe e dependências de flowbits.

## Scripts mantidos

| Script | Função |
|---|---|
| `prepare_pre_cut_pcaps.sh` | Gera a base comum e os três PCAPs cortados |
| `run_pre_cut_comparison.sh` | Executa a comparação por grupo e carga |
| `run_baseline_once.sh` | Executor compartilhado dos modos baseline, precut e cutter |
| `replay_rate.sh` | Funções de taxa/PPS usadas pelos executores e testes |
| `setup_veth.sh` | Prepara ou remove o par de interfaces da bancada |
| `setup_cutter.sh` | Liga, desliga e consulta o XDP |

Para um teste com corte em tempo real, prepare as interfaces, ative o grupo
com `setup_cutter.sh on transport` e use
`sudo env EXPERIMENT_MODE=cutter ./experiments/run_baseline_once.sh transport 500 10 1`.
Ao terminar, use `sudo ./experiments/setup_cutter.sh off`.
