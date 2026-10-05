# SIC Especial

Este projeto consiste na implementação de uma rede Bluetooth Low Energy (BLE) organizada em árvore, constituída por um SINK e dois nós. A rede permite a comunicação entre os diferentes dispositivos através de ligações multi-hop, incluindo mecanismos de routing, segurança e comunicação entre os nós.

## Estrutura

O projeto está dividido em quatro componentes:

- `sync/`: daemon exclusivo do SINK.
- `node/`: daemon comum aos dispositivos IoT.
- `common/`: protocolo, segurança por link e fragmentação do túnel DTLS.
- `support/`: scripts de execução, autenticação e regressão.

## Arquitetura validada

```text
SIC-SINK
   |
SIC-NODE-A
   |
SIC-NODE-B
```

O SINK anuncia a sua presença através de BLE utilizando o seguinte identificador:

01 01 FF

Quando um NODE possui uma ligação válida à rede, anuncia o seu próprio estado através de:

01 02 hop

Durante o processo de discovery, os nós procuram dispositivos SIC próximos e analisam o número de hops anunciado. A escolha do uplink dá prioridade ao menor número de hops e, em caso de empate, ao dispositivo com melhor RSSI.

A estrutura da rede é mantida através das ligações entre os diferentes nós. Cada equipamento possui também um NID próprio de 128 bits, que é utilizado para identificar os dispositivos independentemente do endereço Bluetooth.

Os routers mantêm tabelas de encaminhamento que associam os NIDs às respetivas ligações.

## Funcionalidades

Ao longo do projeto foram implementadas as seguintes funcionalidades:

- discovery por ManufacturerData;
- seleção por hop e RSSI;
- uplink persistente e downlinks GATT por notifications;
- routing bidirecional real `NODE-B -> NODE-A -> SINK`;
- forwarding tables aprendidas por NID;
- protocolo com tipo, origem, destino, serviço, cliente, sequência e payload;
- Inbox com cliente aleatório persistente e ACK end-to-end;
- HMAC-SHA256 por link, contador e rejeição de replay/adulteração;
- CA, certificados com NID/papel, Ed25519, X25519 e HKDF-SHA256;
- certificados DTLS ECDSA P-256 e autenticação mútua;
- heartbeat broadcast, timeout e contadores;
- recuperação em cascata da árvore;
- DTLS 1.2 end-to-end fragmentado sobre BLE;
- interface de consola com estado, rotas, controlos e estatísticas.

## Routing

A rede utiliza uma estrutura em árvore. Neste caso, o NODE-A encontra-se ligado ao SINK e o NODE-B encontra-se ligado ao NODE-A.

Assim, uma mensagem enviada pelo NODE-B para o SINK segue o percurso:

NODE-B → NODE-A → SINK

O caminho inverso também é possível:

SINK → NODE-A → NODE-B

Cada router utiliza a informação existente na sua forwarding table para determinar para onde deve encaminhar uma determinada mensagem.

## Segurança

A comunicação entre os diferentes dispositivos inclui mecanismos de segurança por link. As mensagens são protegidas através de HMAC-SHA256 e de contadores que permitem detetar tentativas de replay.

Para a comunicação end-to-end é utilizado DTLS. Os dispositivos utilizam certificados assinados pela CA do projeto e é realizada autenticação mútua entre os extremos da comunicação.

A comunicação DTLS utiliza DTLS 1.2 e, na configuração utilizada nos testes, a cipher suite:

ECDHE-ECDSA-AES256-GCM-SHA384

## Recuperação da rede

Quando um NODE perde o heartbeat do parent, invalida o hop e o uplink. Se possuir um filho, suspende temporariamente o advertising e desconecta o downlink para evitar conflito entre scan, modo central e modo peripheral no BlueZ. Depois redescobre e recupera o parent, reabre o advertising e permite que a subárvore se ligue novamente.

Foi testado o seguinte cenário:

```text
SINK indisponível
NODE-A timeout
NODE-B timeout
NODE-A recupera SINK
NODE-A reabre downlink
NODE-B recupera NODE-A
heartbeats retomados nos dois nós
```

## Dependências e compilação

O projeto necessita de um ambiente Linux com as seguintes dependências principais: BlueZ, GLib/GIO, SimpleBLE, OpenSSL, CMake 3.21 ou superior e compilador C++17.

Para compilar o SINK:

```bash
cmake -S sync -B sync/build
cmake --build sync/build -j2
```

Para compilar os nós:

```bash
cmake -S node -B node/build
cmake --build node/build -j2
```

Se necessário:

```bash
chmod +x support/*.sh support/tests/*.sh
```

## Execução

O SINK é iniciado através de:

```bash
cd ~/sic-final-release
./support/run-sync.sh
```

Para iniciar o NODE-A:

```bash
cd ~/sic-final-release
./support/run-node.sh SIC-NODE-A SIC-SINK
```

Para iniciar o NODE-B:

```bash
cd ~/sic-final-release
./support/run-node.sh SIC-NODE-B SIC-NODE-A
```

Os comandos `status`, `routes`, `network`, `security-test`, `send texto` e `quit` são escritos dentro do daemon.

## Demonstração do Inbox

Depois de a rede estar estabelecida, pode ser enviada uma mensagem a partir do NODE-B:

```text
send TESTE_FINAL_B_PARA_SINK
```

O SINK apresenta a mensagem e o NID do B. O ACK regressa através de A e aparece no B como `Recebido: TESTE_FINAL_B_PARA_SINK`.

## Demonstração DTLS

Para testar a comunicação DTLS, o servidor pode ser iniciado no SINK:

```bash
cd ~/sic-final-release
./support/run-dtls-server.sh
```

E o cliente no NODE-B:

```bash
cd ~/sic-final-release
./support/run-dtls-client.sh
```

O handshake deve indicar `Verification: OK`, `DTLSv1.2` e `ECDHE-ECDSA-AES256-GCM-SHA384`. Texto escrito em qualquer extremo deve aparecer no outro extremo depois de atravessar o routing BLE.

## Autenticação de peers

O script `support/peer-auth.sh` cria e valida. Cada peer troca apenas os três ficheiros públicos produzidos pelo modo de exportação e executa depois o modo de finalização.

## Regressão

No SINK:

```bash
./support/tests/regression.sh sink
```

Em cada NODE:

```bash
./support/tests/regression.sh node
```

## Estado da implementação

Funcionalidades não implementadas: nenhuma das funcionalidades técnicas previstas ficou por implementar.

Funcionalidades parcialmente implementadas: nenhuma.

## Limitações operacionais

- Como os três dongles estavam no mesmo computador, os parents explícitos tornam a demonstração reproduzível.
- Deve existir apenas uma instância de cada daemon. Instâncias duplicadas ocupam a porta DTLS e provocam notificações repetidas corretamente rejeitadas como replay.

## Autores e contribuição

Elementos do grupo: Mafalda França
Contribuição: 100 %
