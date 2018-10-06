# Packet Extractor

This tool is built for Defcon CTF 2018 Final

## pcap/

put your packets

    2017-12-09_14:15:00.pcap : Hitcon 2018 CTF Final Round -- for test
    
## python file

### stream 

Extract pcap by port (or service)

- Repeated packets detect
    
    - Ignore repeated packet
    
    - Optional : consider only input or whole file. 

- Huge packets detect
    
    - Maximum tolerance size (maximum is setting in config)


### filter
 
Just recheck above output and save to other directory. (In order to avoid loss)

- Black list filtering

### config

All of service enable or not, setting here.



# Note
<span style="color:red">Remember to set your service IP on line 1.</span>

Extractor does not know who you are. QwQ"

