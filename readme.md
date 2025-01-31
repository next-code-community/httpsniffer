---

# **HTTP Sniffer**  

## **Descrizione**  
HTTP Sniffer è un programma Python che intercetta pacchetti HTTP in tempo reale e visualizza informazioni utili direttamente a schermo.  
Supporta la registrazione dei pacchetti su file per analisi successive e permette di leggere dump di pacchetti salvati in precedenza.  

---

## **Requisiti**  
✅ **Linguaggio**: Python 3  
✅ **Moduli richiesti**:  
- `os`
- `pickle`
- `scapy`
- `datetime`
- `optparse`
- `colorama`
- `time`

Puoi installare i moduli mancanti con:  
```bash
pip install scapy colorama
```

---

## **Utilizzo**  

Esegui il programma con i seguenti parametri:  
```bash
python3 main.py -i <interfaccia> [-v True/False] [-w <file>] [-r <file>]
```

### **Opzioni disponibili**:
| Opzione | Descrizione |
|---------|------------|
| `-i, --iface` | Specifica l'interfaccia di rete su cui intercettare i pacchetti |
| `-v, --verbose` | Mostra informazioni dettagliate sui pacchetti intercettati (`True`/`False`, Default: `True`) |
| `-w, --write` | Salva i pacchetti intercettati in un file per analisi future |
| `-r, --read` | Legge pacchetti da un file di dump e ne visualizza le informazioni |

---

## **Output**  
Il programma visualizza:  
✅ **Indirizzi IP** coinvolti nella comunicazione HTTP  
✅ **Metodo HTTP** utilizzato (`GET`, `POST`, ecc.)  
✅ **URL richiesto** dall'host remoto  
✅ **Dati grezzi (RAW Data)** se presenti nel pacchetto intercettato  

Esempio di output in modalità **verbose**:
```
[+] [2025-01-31 14:30:45] 192.168.1.10 : GET => http://example.com/login
[*] [2025-01-31 14:30:45] RAW Data: b'username=admin&password=12345'
```

---

```plaintext
scapy
colorama
```

---

### **Come usare il file `requirements.txt`**  
Per installare tutte le dipendenze, esegui il comando:  
```bash
pip install -r requirements.txt
```

Se usi un ambiente virtuale (`venv`), attivalo prima di installare:  
```bash
python -m venv venv
source venv/bin/activate  # Su Linux/macOS
venv\Scripts\activate     # Su Windows
pip install -r requirements.txt
```



## **Esempi di utilizzo**  

1️⃣ **Sniffare pacchetti su un'interfaccia specifica (es. eth0)**:  
```bash
sudo python3 main.py -i eth0
```

2️⃣ **Sniffare pacchetti senza output dettagliato (verbose disattivato)**:  
```bash
sudo python3 main.py -i wlan0 -v False
```

3️⃣ **Salvare i pacchetti intercettati su file**:  
```bash
sudo python3 main.py -i eth0 -w packets.dump
```

4️⃣ **Leggere pacchetti da un file salvato in precedenza**:  
```bash
python3 main.py -r packets.dump
```

---

## **Note**  
⚠️ **Devi eseguire il programma con privilegi di root** per poter intercettare pacchetti:  
```bash
sudo python3 main.py -i eth0
```

🔹 Assicurati di avere i permessi per sniffare la rete, in alcuni sistemi potrebbe essere necessario abilitare `CAP_NET_RAW`.  

---

## **Autore**  
✍ **Creato da:** bobi.exe & NebulastudioTM  
📅 **Ultimo aggiornamento:** 31/01/2025  

---

