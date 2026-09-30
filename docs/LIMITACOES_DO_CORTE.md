# Limitações relevantes do corte

O foco do TCC é o **algoritmo de adaptação das regras**, com os grupos de
aplicação, transporte e rede/IP. Esta lista concentra os pontos sustentados
por código, testes ou medições, distinguindo seu alcance.

| Ponto | Evidência e alcance |
|---|---|
| **Reconhecimento de aplicação** | No teste offline do SID 2008605, preservar o conteúdo e remover `GET ` fez o alerta desaparecer. A mensagem também pode depender de delimitadores e comprimentos que o corte não conserva. Um prefixo de tamanho fixo não é solução geral. O problema demonstrado foi HTTP; não se afirma que toda regra de aplicação falhe. |
| **Pacotes que passam intactos com regras já adaptadas** | O XDP não corta VLAN, fragmentos IPv4, extensões IPv6, protocolos diferentes de TCP/UDP, payloads acima de 2.048 bytes e alguns pacotes com cabeçalhos inconsistentes. Quando o offset da regra foi deslocado, ela pode procurar no lugar errado nesses pacotes. A divergência foi demonstrada offline com VLAN e SID 2003155. |
| **Regras que consultam campos alterados pelo corte** | Comprimentos e checksums mudam. Uma regra sintética aceita pelo adaptador, que consultava o comprimento UDP, perdeu o alerta após a transformação. O recálculo também pode corrigir um checksum originalmente inválido: é uma consequência do mesmo assunto, não outro problema independente. A relevância depende de as regras selecionadas consultarem esses campos ou anomalias; o teste não prova falha de todo o grupo de rede/transporte. |
| **Custo do caminho com cortador** | Os pilotos mostraram limitação de vazão com XDP/veth, inclusive sem IDS. Ainda não foi separado quanto vem da cópia/checksum e quanto vem da bancada compartilhada. É o ponto de desempenho a investigar; trocar a máquina é uma alternativa a medir. |

## Por que não conservar comprimento e checksum originais?

**Comprimento:** se um datagrama UDP tinha 108 bytes e passa a ter 9, manter
108 no cabeçalho faz o pacote declarar bytes que já não existem. O decodificador
UDP do Suricata verifica essa diferença e retorna erro; IPv4 também verifica
se há menos bytes disponíveis que o comprimento declarado. Portanto, apenas
parar de atualizar esses campos não resolve a compatibilidade das regras.
Fontes: [decodificador UDP](https://raw.githubusercontent.com/OISF/suricata/suricata-8.0.7/src/decode-udp.c)
e [decodificador IPv4](https://raw.githubusercontent.com/OISF/suricata/master/src/decode-ipv4.c).

**Checksum:** é uma questão separada. Nos experimentos atuais, o Suricata roda
com `-k none`, que desabilita a validação de checksums. Conservar o checksum
original pode ser uma alternativa experimental nesse ambiente, mas não resolve
os comprimentos inconsistentes nem produz, em geral, um checksum válido para
o pacote modificado. Não foi feita essa alteração no código.
Fonte: [opção de checksum do Suricata](https://docs.suricata.io/en/suricata-8.0.1/command-line-options.html#cmdoption-k).

## Uma limitação adicional do adaptador

Uma regra sintética com `entropy` foi aceita embora a operação examinasse
bytes não conservados; o alerta desapareceu após o corte. É um caso concreto
de opção não tratada pelo adaptador, **fora dos três conjuntos atuais**.
Delimita as opções suportadas, sem demonstrar falha nas regras desses conjuntos.

Os testes semânticos citados usaram PCAPs construídos offline para representar
a transformação, não o caminho XDP completo. Os registros locais estão em
`/tmp/tcc-audit/` e são temporários.

Os limites de configuração permanecem no [escopo](escopo-algoritmo.md).
A dependência de `flowbit` encontrada pertence à
[seleção das regras](../application-rules/README.md), e não a uma alteração
causada pelo corte. Características do algoritmo, hipóteses sem falha demonstrada
no cenário e cuidados gerais de medição não são tratados aqui como pendências.
