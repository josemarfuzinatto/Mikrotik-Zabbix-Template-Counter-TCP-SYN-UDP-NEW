# Template Contador de Pacotes TCP/SYN e UDP/NEW
SYN/TCP e UDP/NEW basicamente são pacotes de abertura de novas conexões, cada tipo de seu protocolo.

Contando eles é possível se ter um panorama geral de quantidade de conexões TCP e UDP em PPS e Bytes.

Em cenários onde se usa CCR2216 com Offload corretamente configurado, os pacotes de abertura são basicamente os únicos pacotes que "sobem" para a CPU antes da rota ser instalada no hardware. POR ISSO, é importante contabiliza-los.

Também é possivel pegar ataques DDoS do tipo SYN Flood e qualquer amplificação UDP (53 e 123 por exemplo)

O Template é feito para Zabbix 7 e cria uma Dashboard para o equipamento com os dados analisados. DICA: Compare o gráfico de UDP/PPS com o grafico de CPU de seu Mikrotik e veja exatamente quando se teve DDoS.

### PASSO A PASSO:
## 1 - Habilitar uma comunidade SNMP com permissão de escrita 
(IMPORTANTE LIMITAR ao IP do Zabbix)
```
/snmp community
add addresses=100.100.100.50/32 name=zbx_wr1te write-access=yes
/snmp
set contact=xxx@exemplo.com.br enabled=yes location=Chapeco-SC
``` 
Substitua ```100.100.100.50/32``` pelo IP do seu Zabbix.

## 2 - Criar as regras de firewall filter no RouterOS que farão a coleta
```
/ip firewall filter
add action=passthrough chain=forward comment=MONITOR_TCP_SYN_COUNT connection-state=new protocol=tcp tcp-flags=syn
add action=passthrough chain=forward comment=MONITOR_UDP_NEW_COUNT connection-state=new protocol=udp
```

## 3 - Criar o Script Conforme abaixo:
Use o nome que quiser, eu chamo de "get_counters_tcp_udp_json"
# Script RouterOS:
```
:local output "{"
:local first true

# Lista exata dos comentarios
:local listaRegras {"MONITOR_TCP_SYN_COUNT"; "MONITOR_UDP_NEW_COUNT"}

:foreach nomeRegra in=$listaRegras do={
    # Busca os IDs. Isso retorna uma lista/array.
    :local foundIDs [/ip firewall filter find comment=$nomeRegra]
    
    # Verifica se a lista nao esta vazia
    :if ([:len $foundIDs] > 0) do={
        
        #Pegamos apenas o primeiro ID da lista para garantir
        :local singleID [:pick $foundIDs 0]
        
        # Inicializa variaveis para evitar erro
        :local packets 0
        :local bytes 0
        
        # Tenta pegar os valores
        :do {
            :set packets [/ip firewall filter get $singleID packets]
            :set bytes   [/ip firewall filter get $singleID bytes]
        } on-error={
            :put ("Erro ao ler dados da regra: " . $nomeRegra)
        }
        
        # Logica da virgula
        :if ($first = false) do={ :set output ($output . ",") }
        :set first false
        
        # Monta o JSON
        :set output ($output . "\"" . $nomeRegra . "\": {\"packets\": " . $packets . ", \"bytes\": " . $bytes . "}")
        
    } else={
        # Debug: Se nao achar a regra, avisa no terminal para voce saber
        :put ("AVISO: Nao encontrei nenhuma regra com o comentario: " . $nomeRegra)
    }
}

:set output ($output . "}")

# Imprime o JSON final
:put $output
```
Para testar se deu boa, pode rodar direto no terminal do mikrotik: ```/system/script/run get_counters_tcp_udp_json```
verá um resultado como: <br>
```{"MONITOR_TCP_SYN_COUNT": {"packets": 708555894, "bytes": 43545004564},"MONITOR_UDP_NEW_COUNT": {"packets": 32772666966, "bytes": 4195821380659}```


## 4 - Identificar o correto ID do Script com SNMP Walk:
snmpwalk -v2c -c comunity ip 1.3.6.1.4.1.14988.1.1.8.1.1.2

## 5 - Importar o tamplate para o Zabbix
Feito para Zabbix 7.

## 6 - Adicionar o Host criando a macro {$IDSCRIPT} com o ID correspondente ao Script. 
(pode criar o item macro no host mesmo) e usar a entrada "{$IDSCRIPT}" apontando para o value X (numero encontrado do script).

Em geral segue a lógica de:
1.3.6.1.4.1.14988.1.1.8.1.1.2.1 = primeiro script do mikrotik <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.2 = segundo script <br>
1.3.6.1.4.1.14988.1.1.8.1.1.2.3 = terceiro, e asim por diante. <br>
SE teve algum script excluido o routeros tmb conta o ID dele e não reutiliza mais. Então, por exemplo, se o terceiro e quarto scripts que existiam e foram excluidos, o ID será o 5.


### PASSO A PASSO COMPLETO:
https://github.com/user-attachments/assets/2ff2ff3a-7182-4e63-ac5f-89bdab45347e

### Host Dashboard:
<img width="1920" height="1523" alt="Image" src="https://github.com/user-attachments/assets/36590a45-a5d0-4c4f-8b18-f2f08e3f95a1" />
