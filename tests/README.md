# Testes

Execute os comandos na raiz do projeto.

## Sem privilegios

```bash
make test
```

Verifica intervalos por pacote, adaptacao de offsets, exclusao de protocolos
de aplicacao, SIDs pareados e consistencia dos arquivos de regras/summaries.
Os testes C++ usam UBSan. Os executaveis ficam em `build/`.

## XDP e Suricata: positivo e negativo UDP

Requer clang, g++, libbpf/libelf/zlib, Suricata e permissao para carregar BPF
(kernel >= 5.18). Usa a SID 2008414, ET SCAN Cisco Torch TFTP Scan.

Prepare um diretorio novo por execucao, pois o Suricata pode acrescentar logs:

```bash
make
TEST_DIR=$(mktemp -d /tmp/tcc-e2e.XXXXXX)
mkdir -p "$TEST_DIR/original-log" "$TEST_DIR/washed-log"

g++ -std=c++11 -Wall -Wextra -pedantic tests/make_test_pcap.cpp \
  -o "$TEST_DIR/make_test_pcap"
g++ -std=c++11 -Wall -Wextra -pedantic tests/wash_pcap.cpp \
  -lbpf -lelf -lz -o "$TEST_DIR/wash_pcap"

"$TEST_DIR/make_test_pcap" "$TEST_DIR/original.pcap"
rg 'sid:2008414;' suricata.rules > "$TEST_DIR/original.rules"
./build/alg "$TEST_DIR/original.rules" "$TEST_DIR/adapted.rules" \
  > "$TEST_DIR/summary.txt"

sudo "$TEST_DIR/wash_pcap" build/af_xdp_kern.o "$TEST_DIR/summary.txt" \
  "$TEST_DIR/original.pcap" "$TEST_DIR/washed.pcap"
```

Para essa regra isolada, o intervalo e `2-22`, o offset adaptado e `0` e o
resultado esperado e `PASS: 2 packets, 484 -> 126 bytes`. O executor verifica
payload, comprimentos, campos preservados e checksums com BPF_PROG_TEST_RUN.
Use sempre **Merged**, nunca **Adjusted**, para configurar os mapas.

Compare os alertas com a mesma configuracao:

```bash
for mode in original washed; do
  rules="$TEST_DIR/original.rules"
  if [ "$mode" = washed ]; then rules="$TEST_DIR/adapted.rules"; fi
  suricata -c /dev/null --runmode single \
    -r "$TEST_DIR/$mode.pcap" -S "$rules" -l "$TEST_DIR/$mode-log" \
    --set vars.address-groups.HOME_NET=10.0.0.0/8 \
    --set vars.address-groups.EXTERNAL_NET=any \
    --set classification-file=/dev/null --set reference-config-file=/dev/null \
    --set threshold-file=/dev/null --set outputs.0=fast \
    --set outputs.0.fast.enabled=yes --set outputs.0.fast.filename=fast.log
done
diff -u "$TEST_DIR/original-log/fast.log" "$TEST_DIR/washed-log/fast.log"
```

Esperado: um alerta SID 2008414 no positivo (porta de origem 12345) e nenhum
no negativo (12346), com logs iguais.

## Limites

O executor aceita PCAP classico little-endian, Ethernet/IPv4 sem opcoes,
TCP/UDP nao fragmentado, checksums validos e payload de ate 2048 bytes.
Esse teste nao certifica outros formatos ou conjuntos de regras. As amostras
antigas, geradas com outro conjunto de intervalos, estao em `archive/e2e/`.
O grupo `application` continua suspenso; veja [a justificativa](../application-rules/README.md).
