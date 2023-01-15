import pcap
import dpkt
import binascii
import argparse
import json
import os
import time

global pkt

def bssid(mac):
  global pkt
  mac = bytearray(mac).decode()
  flag = 0
  if mac == "ffffffffffff":
      return 0
  mac = f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}"
  with open('db.json', "r") as json_file:
      json_data = json.load(json_file)
      for mac_addr,dic in json_data.items():
          if mac_addr == mac:
              ess = essid(pkt)
              dic[ess] = dic[ess]+1
              flag = 1
              break
  if flag == 0:
      json_data[mac] = {essid(pkt):0}
  with open('db.json','w') as outfile:
      json.dump(json_data,outfile)
  return 1

def essid(pkt):
  essid=''
  for i in [48,60]:
      pkt = bytearray(pkt)
      flag = pkt[i]
      if flag == 0:
          leng = pkt[i+1]
          for j in range(i+2,i+2+leng):
              essid = essid+chr(pkt[j])
          if essid[0] == '\u0000':
              return "This is Hidden API"
          return essid

def print_log():
  os.system("clear")
  print("BSSID\t\t\tBeacons\t\tESSID\n")
  with open('db.json','r') as data:
      json_data = json.load(data)
      for mac_addr,dic in json_data.items():
          if mac_addr == "ff:ff:ff:ff:ff:ff":
              continue
          print(f"{mac_addr}\t",end='')
          for essid,beacons in dic.items():
              print(f"{beacons}\t\t",end='')
              print(f"{essid}")

def sniffer(interface):
  global pkt
  sniffer = pcap.pcap(name=interface,promisc=True,immediate=True,timeout_ms=50)
  for ts, pkt in sniffer:
      try:
          radiotap_len = binascii.hexlify(pkt[2:3])
          radiotap_len = int(radiotap_len, 16)
          if radiotap_len != 24:
              continue 
          else:
              wlan = dpkt.ieee80211.IEEE80211(pkt[radiotap_len:])
              chk = bssid(binascii.hexlify(wlan.mgmt.bssid))
              if chk == 0:
                  raise Exception()
              print_log()
              #time.sleep(1)
      except:
          pass

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument('arg1')
  args = parser.parse_args()
  try:
    with open("./db.json","w") as f:
      f.write('{"ff:ff:ff:ff:ff:ff": 0}')
      f.close()
  except:
    pass
  sniffer(args.arg1)
