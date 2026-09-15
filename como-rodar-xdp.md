# Teste do packet washer com XDP/eBPF

Este arquivo resume o fluxo atual para compilar, carregar e testar o `af_xdp_kern.c`.

A implementação atual faz:

```text
intervals_map
    |
    V
lê os intervalos que devem ser preservados
    |
    V
compact_payload()
    |
    V
copia os bytes preservados para o início do payload
    |
    V
calcula quantos bytes sobraram
    |
    V
cut_packet()
    |
    V
remove a sobra do final do pacote
```

No código atual:

```c
#define MAX_INTERVALS 16
#define MAX_PAYLOAD_BYTES 2048
```

Portanto, para estes testes, o programa aceita no máximo 16 intervalos e payloads de até 2048 bytes.

---

## 1. Compilar

Na raiz do projeto:

```bash
make clean
make
```

Ao final devem existir pelo menos:

```text
alg
af_xdp_kern.o
```

Para conferir:

```bash
ls -lh alg af_xdp_kern.o
```

---

## 2. Limpar uma carga anterior

Antes de carregar novamente o programa XDP:

```bash
sudo rm -f /sys/fs/bpf/jmm23_xdp
sudo rm -rf /sys/fs/bpf/jmm23_maps
sudo mkdir -p /sys/fs/bpf/jmm23_maps
```

---

## 3. Carregar o programa eBPF

```bash
sudo bpftool prog load \
    af_xdp_kern.o \
    /sys/fs/bpf/jmm23_xdp \
    type xdp \
    pinmaps /sys/fs/bpf/jmm23_maps
```

Se o comando terminar sem erro, o kernel/verifier aceitou o programa.

Para conferir os maps:

```bash
ls -l /sys/fs/bpf/jmm23_maps
```

Devem aparecer:

```text
intervals_map
interval_cnt
```

Também é possível conferir o programa carregado com:

```bash
sudo bpftool prog show
```

---

## 4. Teste simples: preservar `0-3` e `8-11`

Vamos usar:

```text
payload original:
abcdefghijklmnop
```

Posições:

```text
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p
```

Intervalos preservados:

```text
0-3
8-11
```

Resultado esperado:

```text
abcdijkl
```

### 4.1. Informar que existem 2 intervalos

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/interval_cnt \
    key hex 00 00 00 00 \
    value hex 02 00 00 00
```

### 4.2. Inserir o intervalo `0-3`

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/intervals_map \
    key hex 00 00 00 00 \
    value hex 00 00 00 00 03 00 00 00
```

### 4.3. Inserir o intervalo `8-11`

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/intervals_map \
    key hex 01 00 00 00 \
    value hex 08 00 00 00 0b 00 00 00
```

### 4.4. Conferir os maps

```bash
sudo bpftool map dump pinned /sys/fs/bpf/jmm23_maps/interval_cnt
sudo bpftool map dump pinned /sys/fs/bpf/jmm23_maps/intervals_map
```

---

## 5. Criar um pacote TCP de teste

Este comando gera um pacote Ethernet + IPv4 + TCP com o payload `abcdefghijklmnop`.

```bash
python3 - <<'PY'
import struct
import socket

payload = b"abcdefghijklmnop"

eth = (
    bytes.fromhex("020000000002") +
    bytes.fromhex("020000000001") +
    struct.pack("!H", 0x0800)
)

total_len = 20 + 20 + len(payload)

ip = struct.pack(
    "!BBHHHBBH4s4s",
    0x45,
    0,
    total_len,
    1,
    0,
    64,
    6,
    0,
    socket.inet_aton("10.0.0.1"),
    socket.inet_aton("10.0.0.2")
)

tcp = struct.pack(
    "!HHLLBBHHH",
    12345,
    80,
    0,
    0,
    5 << 4,
    0x18,
    65535,
    0,
    0
)

packet = eth + ip + tcp + payload

with open("test_packet.bin", "wb") as f:
    f.write(packet)

print("packet size:", len(packet))
print("payload:", payload)
PY
```

Saída esperada:

```text
packet size: 70
payload: b'abcdefghijklmnop'
```

---

## 6. Executar o XDP sem anexar à interface de rede

```bash
sudo bpftool prog run \
    pinned /sys/fs/bpf/jmm23_xdp \
    data_in test_packet.bin \
    data_out output_packet.bin
```

Saída esperada:

```text
Return value: 2
```

`2` corresponde a `XDP_PASS`.

---

## 7. Conferir o corte

O pacote original possui:

```text
14 bytes Ethernet
20 bytes IPv4
20 bytes TCP
16 bytes payload
----------------
70 bytes
```

Foram preservados 8 bytes do payload:

```text
0-3   = 4 bytes
8-11  = 4 bytes
```

Logo, o pacote final deve possuir:

```text
70 - 8 = 62 bytes
```

Confira:

```bash
stat -c '%s' output_packet.bin
```

Resultado esperado:

```text
62
```

Agora confira os últimos 8 bytes:

```bash
tail -c 8 output_packet.bin
echo
```

Resultado esperado:

```text
abcdijkl
```

Se os três resultados forem:

```text
Return value: 2
62
abcdijkl
```

a compactação e o corte funcionaram corretamente.

---

## 8. Como trocar os intervalos para novos testes

Cada entrada de `intervals_map` contém:

```c
struct interval {
    __u32 start;
    __u32 end;
};
```

Os valores enviados com `bpftool` estão em little-endian.

Por exemplo:

```text
start = 500
end   = 1363
```

Em hexadecimal de 32 bits little-endian:

```text
500  = f4 01 00 00
1363 = 53 05 00 00
```

Então:

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/intervals_map \
    key hex 01 00 00 00 \
    value hex f4 01 00 00 53 05 00 00
```

Para converter qualquer número decimal para os quatro bytes usados pelo `bpftool`:

```bash
python3 - <<'PY'
import struct

for value in [500, 1363]:
    print(value, struct.pack("<I", value).hex(" "))
PY
```

Saída:

```text
500 f4 01 00 00
1363 53 05 00 00
```

---

## 9. Teste com intervalos próximos dos produzidos pelo algoritmo

Exemplo:

```text
0-313
500-1363
```

Defina `count = 2`:

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/interval_cnt \
    key hex 00 00 00 00 \
    value hex 02 00 00 00
```

Intervalo `0-313`:

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/intervals_map \
    key hex 00 00 00 00 \
    value hex 00 00 00 00 39 01 00 00
```

Intervalo `500-1363`:

```bash
sudo bpftool map update \
    pinned /sys/fs/bpf/jmm23_maps/intervals_map \
    key hex 01 00 00 00 \
    value hex f4 01 00 00 53 05 00 00
```

Para esse teste o payload precisa possuir pelo menos 1364 bytes se quisermos observar os dois intervalos completos.

Os intervalos preservados possuem:

```text
0-313       = 314 bytes
500-1363    = 864 bytes
---------------------
total       = 1178 bytes
```

Portanto, depois da compactação:

```text
0-313 permanece em 0-313
500-1363 passa para 314-1177
```

O novo payload deve terminar na posição `1177`.

---

## 10. Fluxo rápido para repetir um teste

Depois que o código já estiver compilando, o ciclo normal é:

```bash
make
```

```bash
sudo rm -f /sys/fs/bpf/jmm23_xdp
sudo rm -rf /sys/fs/bpf/jmm23_maps
sudo mkdir -p /sys/fs/bpf/jmm23_maps
```

```bash
sudo bpftool prog load \
    af_xdp_kern.o \
    /sys/fs/bpf/jmm23_xdp \
    type xdp \
    pinmaps /sys/fs/bpf/jmm23_maps
```

Depois carregue `interval_cnt` e os elementos de `intervals_map`.

Por fim:

```bash
sudo bpftool prog run \
    pinned /sys/fs/bpf/jmm23_xdp \
    data_in test_packet.bin \
    data_out output_packet.bin
```

E confira:

```bash
stat -c '%s' output_packet.bin
```

```bash
xxd output_packet.bin
```

ou, quando souber o tamanho esperado do payload:

```bash
tail -c TAMANHO output_packet.bin
echo
```

---

## 11. Parte principal adicionada ao código

A configuração dos intervalos fica nos BPF maps:

```c
#define MAX_INTERVALS 16
#define MAX_PAYLOAD_BYTES 2048

struct interval {
    __u32 start;
    __u32 end;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_INTERVALS);
    __type(key, __u32);
    __type(value, struct interval);
} intervals_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} interval_cnt SEC(".maps");
```

`interval_cnt` informa quantos elementos de `intervals_map` são válidos.

A compactação funciona conceitualmente assim:

```text
write_pos = 0

para cada intervalo [start, end]:
    copiar os bytes do intervalo
    para payload[write_pos...]

    write_pos += tamanho do intervalo

novo tamanho do payload = write_pos
delta = tamanho antigo - novo tamanho

cut_packet(delta)
```

No código eBPF, a cópia é feita com `bpf_loop()` e acesso ao pacote pelos helpers XDP.

---

## 12. Estado atual

Já foi validado com sucesso:

```text
payload original:
abcdefghijklmnop

intervalos:
0-3
8-11

payload resultante:
abcdijkl
```

Resultado observado:

```text
Return value: 2
62
abcdijkl
```

Portanto, neste ponto já foi comprovado que:

```text
BPF map
→ leitura dos intervalos
→ compactação
→ cálculo do delta
→ bpf_xdp_adjust_tail()
→ XDP_PASS
```

funciona no teste local com `bpftool prog run`.

A próxima etapa é automatizar a carga dos intervalos produzidos pelo algoritmo C++ para os BPF maps, eliminando a necessidade de inserir cada intervalo manualmente com `bpftool`.