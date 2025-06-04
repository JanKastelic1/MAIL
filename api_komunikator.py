import requests
import xml.etree.ElementTree as ET
import json
from email.message import EmailMessage
import win32com.client
import os
from datetime import datetime, timezone
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText



URL_PALO = "https://security.paloaltonetworks.com/json/"
URL_FORTI = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"

URL_PALO_CRITICAL = "https://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories?severity=CRITICAL"

r = requests.get(url=URL_PALO)
f = requests.get(url=URL_FORTI)
critical = requests.get(url=URL_PALO_CRITICAL)


data = r.json()
data_palo_critical = critical.json()
data_forti = f.text
  
root = ET.fromstring(data_forti)

results = []

def basicPaloAltoVuln():

    current_month = datetime.now().strftime("%B %Y")
    current_month_str = str(current_month)
    wrapped = f"( {current_month_str} )"
    now = datetime.now(timezone.utc)

    for item in data:
        threatSeverity = item['threatSeverity']
        baseSeverity = item['baseSeverity']
        title = item['title']
        affected = item['affected']
        affected = ', '.join(affected)
        date = item['date']
        
        input_date = datetime.fromisoformat(date.replace("Z", "+00:00"))

        updated = item['updated']
        problem = item['problem'][0]['value']
        solution = item['solution'][0]['value']
        print("TITLE:", title)
        #print (f'Kritičnost: {baseSeverity}\nNaslov:  {title}\nOkuženi:  {affected}\nProblem: {problem}\nRešitev: {solution};\n')

        if input_date.month == now.month and input_date.year == now.year:
            print("Same month")
            new_dict = {'Kriticnost': baseSeverity,
                        'Naslov': title,
                        'Datum' : date,
                        'Updated' : updated,
                        'Okuzeni': affected,
                        'Problem': problem,
                        'Resitev': solution}
            results.append(new_dict)
        else:
            print("Different month")

        #print(input_date)
    #print(results)
    return results

def basicFortiVuln():
    for item in root.findall(".//{*}item"):
        naslov = item.find("{*}title").text
        link = item.find("{*}link").text
        opis = item.find("{*}description").text
        #print(f"Naslov: {naslov}\nLink: {link}\nOpis: {opis}\n")
        new_dictionary = {'Naslov': naslov,
                        'Link': link,
                        'Opis': opis,
                        }
        results.append(new_dictionary)
    return results

def PaloAltoCriticalEvents():

    rezultati = []

    for cve in data_palo_critical['data']:
        idid = cve['cveMetadata']['cveId']
        naslov = cve['containers']['cna']['title']
        datum = cve['containers']['cna']['datePublic']
        problemi = []
        vendors = []
        products = []
        skupen_vendor_produkt = []
        for i in cve['containers']['cna']['problemTypes']:
            for j in i['descriptions']:
                problem = j['description']
                problemi.append(problem)
        for aff in cve['containers']['cna']['affected']:
            vendor = aff['vendor']
            vendors.append(vendor)
            skupen_vendor_produkt.append(vendor)
            product = aff['product']
            skupen_vendor_produkt.append(product)
            products.append(product)
            #print(vendors)
            #print(products)
        #print(skupen_vendor_produkt)
        #print(problemi)
        for opis in cve['containers']['cna']['descriptions']:
            pravi_opis = opis['value']
            #print(pravi_opis)
        for ref in cve['containers']['cna']['references']:
            link = ref['url']
            #print(link)
        for conf in cve['containers']['cna'].get('configurations', []):
            val = conf.get('value', '')
        for work in cve['containers']['cna']['workarounds']:
            workaround = work['value']
            #print(workaround)
        #print(cve['containers']['cna'].keys())
        for sol in cve['containers']['cna']['solutions']:
            solution = sol['value']
            #print(solution)
        for exp in cve['containers']['cna'].get('exploits',[]):
            exploit = exp.get('value','')
            #print(exploit)
        nov_slovar = {'ID': idid,
                        'Naslov': naslov,
                        'Datum': datum,
                        'Problemi': problemi,
                        #'Vendorji': vendors,
                        #'Produkti': products,
                        'Skupen-Vendor-Produkt par': skupen_vendor_produkt,
                        'Opis' : pravi_opis,
                        'Link' : link,
                        'Konfiguracija' : val,
                        'Workaround': workaround,
                        'Resitev' : solution,
                        'Exploiti' : exploit}
        rezultati.append(nov_slovar)

#print(len(rezultati))

#print(rezultati)

    return rezultati

def primerjalnikJsona(data_end,data_end_new):
    koncni_result = []

    for entry in data_end_new:
        if entry not in data_end:
            raz_id = entry['ID']
            raz_naslov = entry['Naslov']
            raz_datum = entry['Datum']
            raz_problemi = entry['Problemi']
            raz_vendor_produkt = entry['Skupen-Vendor-Produkt par']
            raz_opis = entry['Opis']
            raz_link = entry['Link']
            raz_konfiguracija = entry['Konfiguracija']
            raz_workaround = entry['Workaround']
            raz_resitev = entry['Resitev']
            raz_exploiti = entry['Exploiti']
            #print(raz_id,raz_naslov,raz_datum,raz_problemi,raz_vendor_produkt,raz_opis,raz_link,raz_konfiguracija,raz_workaround,raz_resitev,raz_exploiti)
            nov_slovar_2 = {'ID': raz_id,
                        'Naslov': raz_naslov,
                        'Datum': raz_datum,
                        'Problemi': raz_problemi,
                        #'Vendorji': vendors,
                        #'Produkti': products,
                        'Skupen-Vendor-Produkt par': raz_vendor_produkt,
                        'Opis' : raz_opis,
                        'Link' : raz_link,
                        'Konfiguracija' : raz_konfiguracija,
                        'Workaround': raz_workaround,
                        'Resitev' : raz_resitev,
                        'Exploiti' : raz_exploiti}
            koncni_result.append(nov_slovar_2)
        else:
            print("Ni razlik")
    print(koncni_result)
    return koncni_result


def main():

    """rezultati = PaloAltoCriticalEvents()

    if not os.path.exists("output.json"):
        # First run: save initial data
        with open("output.json", "w", encoding="utf-8") as f:
            json.dump(rezultati, f, indent=4, ensure_ascii=False)
        print("Initial output.json created.")
        with open("New_json.json", "w", encoding="utf-8") as f:
            json.dump(rezultati, f, indent=4, ensure_ascii=False)
    else:
        with open("New_json.json", "r", encoding="utf-8") as f2:
            data_k = json.load(f2)
# Step 2: Write that content to file1.json (overwriting it)
        with open("output.json", "w", encoding="utf-8") as f1:
            json.dump(data_k, f1, indent=4, ensure_ascii=False)


    with open("output.json", "r", encoding="utf-8") as lmao:
        data_end = json.load(lmao)

    with open("New_json.json", "r", encoding="utf-8") as rofl:
        data_end_new = json.load(rofl)
    
    #email_body = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in rezultati[3].items()])

    #email_body2 = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in results[4].items()])

    #email_body3 = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in koncni_result[0].items()])

    koncni_result = primerjalnikJsona(data_end,data_end_new)

    email_body3 = "<hr>".join(
        [
            "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in item.items()])
            for item in koncni_result
        ]
    )


    if len(koncni_result) > 0:
        outlook = win32com.client.Dispatch("Outlook.Application")
        mail = outlook.CreateItem(0)
        mail.Subject = "Critical CVE Alert"
        mail.To = "Jan.Kastelic@src.si"
        mail.HTMLBody = email_body3
        mail.Send()
    else:
        print('Nič za poslati!')"""

    #res = basicPaloAltoVuln()
    #res2 = basicFortiVuln()

    #print(res,res2)

    primer = basicPaloAltoVuln()

    print(primer)

    with open("neki.json", "w", encoding="utf-8") as f1:
        json.dump(primer, f1, indent=4, ensure_ascii=False)

    email_body3 = "<hr>".join(
        [
            "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in item.items()])
            for item in primer
        ]
    )

    sender_email = "src-soc@src.si"
    receiver_email = "src-soc@src.si"
    subject = "HTML Test Email"
    smtp_server = "172.27.2.70"
    smtp_port = 25

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    # Attach HTML content
    msg.attach(MIMEText(email_body3, "html"))

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.sendmail(sender_email, receiver_email, msg.as_string())
    
    """outlook = win32com.client.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)
    mail.Subject = "Critical CVE Alert"
    mail.To = "src-soc@src.si"
    mail.HTMLBody = email_body3
    mail.Send()"""

    print(email_body3)
    

if __name__ == "__main__":
    main()


"""with open("output.json", "r", encoding="utf-8") as lmao:
    data_end = json.load(lmao)

with open("New_json.json", "r", encoding="utf-8") as rofl:
    data_end_new = json.load(rofl)



#email_body = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in rezultati[3].items()])

email_body2 = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in results[4].items()])

#email_body3 = "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in koncni_result[0].items()])

email_body3 = "<hr>".join(
    [
        "<br>".join([f"<h3>{key}:</h3><p>{value}</p>" for key, value in item.items()])
        for item in koncni_result
    ]
)


if len(koncni_result) > 0:
    outlook = win32com.client.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)
    mail.Subject = "Critical CVE Alert"
    mail.To = "Jan.Kastelic@src.si"
    mail.HTMLBody = email_body3
    mail.Send()
else:
    print('Nič za poslati!')


if not os.path.exists("output.json"):
    # First run: save initial data
    with open("output.json", "w", encoding="utf-8") as f:
        json.dump(rezultati, f, indent=4, ensure_ascii=False)
    print("Initial output.json created.")
else:
    with open("New_json.json", "r", encoding="utf-8") as f2:
        data_k = json.load(f2)

# Step 2: Write that content to file1.json (overwriting it)
    with open("output.json", "w", encoding="utf-8") as f1:
        json.dump(data_k, f1, indent=4, ensure_ascii=False)



with open("New_json.json", "w", encoding="utf-8") as f:
    json.dump(rezultati, f, indent=4, ensure_ascii=False)"""



#print(json.dumps(data_palo_critical['data'], indent=2))