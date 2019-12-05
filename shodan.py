#!/usr/bin/env python3

import shodan
import argparse
import requests
from os import system, name
do_clear = False
api = None
ip = ""
def menu():
    print("-"*80)
    print("1 - Show IP")
    print("2 - Shodan search")
    print("3 - Scan a host")
    print("0 - Exit")

def clear(): 
    if name == 'nt': 
        system('cls') 
    else: 
        system('clear')

def search(query):
    try:
        results = api.search(query)
        for item in results["matches"]:
            ip_str = item.get("ip_str")
            hostname = ""
            port = ""
            isp = ""
            country = ""
            asn = ""
            if len(item.get("hostnames")) > 0:
                hostname += str(item.get("hostnames")[0])
            port += str(item.get("port"))
            isp += str(item.get("isp"))
            try:
                country += item.get("location").get("country_code")
            except:
                country = "ZZ"
            asn += str(item.get("asn"))
            if hostname != "":
                print("{:3} {:16} {:6} {:9} {:22} {:19}".format(country, ip_str, port, asn, isp[:20], hostname[:19]))
            else:
                print("{:3} {:16} {:6} {:9} {:40}".format(country, ip_str, port, asn, isp[:39]))
    except Exception as e:
        print("Failed with error: ", e, sep="")

def host(query):
    try:
        clear()
        results = api.host(query)
        print("IP: ", results.get("ip_str"))
        print("Hostnames: {}".format(results.get("hostnames")))
        print("Country: {} ({})".format(results.get("country_name"), results.get("country_code")))
        print("ISP: {} ({})".format(results.get("isp"), results.get("asn")))
        print("Organization: {}".format(results.get("org")))
        print("Open ports: {}".format(results.get("ports")))
        print("\n\n")
    except Exception as e:
        print("Failed with error: ", e, sep="")


def show_ip():
    global ip
    if ip == "":
        url = "https://ipv4.wtfismyip.com/text"
        try:
            resp = requests.get(url)
            ip = resp.text
            clear()
            print("Your IP: ", resp.text, sep="")
        except Exception as e:
            print("Failed with error: ", e, sep="")
    else:
        clear()
        print("Your IP: ", ip, sep="")


if __name__ == "__main__":
    loop = True
    API_KEY = input("Please enter your Shodan API key: ")
    api = shodan.Shodan(API_KEY)
    while loop:
        if do_clear:
            clear()
        menu()
        option = input("Your choice> ")

        if option == "1":
            show_ip()
        elif option == "2":
            q = input("Search term: ")
            search(q)
        elif option == "3":
            q = input("IP: ")
            host(q)
        elif option == "0":
            loop = False
        else:
            do_clear = True
            input("Wrong option. Please retry... PRESS ENTER")
