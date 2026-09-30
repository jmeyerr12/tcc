# Situacao do conjunto de aplicacao

**Aplicacao continua no objetivo do TCC.** As restricoes abaixo descrevem o
conjunto e a implementacao atuais, nao a retirada dessa categoria da avaliacao.

O cenario `application` esta desabilitado nos scripts de experimento.
O algoritmo exclui protocolos de aplicacao no header da regra, mesmo quando
o conteudo possui uma janela finita no payload bruto: a identificacao do
protocolo pode depender de bytes fora dessa janela.

Foram retiradas dos dois lados da comparacao as regras:

| SID | Protocolo | Regra |
|---|---|---|
| 2024212 | SMB | ETERNALCHAMPION Sync Request |
| 2057247 | SSH | Pygmy Goat SSH ed25519 Key |
| 2008605 | HTTP | Stompy Web Application Session Scan |
| 2009477 | HTTP | SQLBrute SQL Scan Detected |

As versoes originais estao em `excluded-application.rules`, para rastreabilidade
e testes de rejeicao. Esse arquivo nao deve ser carregado pelos experimentos.
O arquivo fonte geral `../suricata.rules` permanece preservado.

`original-application.rules` e `original-application-adapted.rules` agora
contem os mesmos quatro SIDs restantes. Tres regras TCP nao inspecionam
payload. A unica regra UDP com payload, SID 2069043, consulta o flowbit
`ET.IKE.MS_Sec_VID`, cujo produtor esta ausente. O `flowbit` funciona como uma
marca na conexao: `set` grava a marca e `isset` exige que ela exista.
No arquivo fonte `../suricata.rules`, quem a grava e o SID 2069042, ausente
dos conjuntos selecionados de aplicacao e transporte. Sua segunda busca de
conteudo nao tem janela finita, fora do escopo atual do adaptador.
Isso afeta os conjuntos originais e adaptados; nao foi causado pelo corte.
A regra 2069043 permanece nos arquivos para registrar essa limitacao.
Referencia: [flowbits no Suricata](https://docs.suricata.io/en/suricata-8.0.1/rules/flow-keywords.html#flowbits).

O summary atual descreve apenas esse conjunto residual: intervalo `16-23`,
adaptado para `0-7`. Isso nao torna o conjunto apto ao experimento. Nao se
deve reutilizar o antigo intervalo `4-183` com essas regras.

Os resultados anteriores com oito regras e aproximadamente 78% de reducao
sao registros historicos, sem demonstracao de equivalencia de deteccao.
Para retomar essa categoria, sera necessario selecionar e validar outro
conjunto, com dependencias completas. A exclusao atual nao certifica os
demais conjuntos nem resolve as outras limitacoes apontadas na auditoria.

O calculo de intervalos continua por pacote, independente das opcoes `flow`.
Nenhum prefixo foi acrescentado aos intervalos para preservar protocolos.
