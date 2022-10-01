# Script to get a random number (< 10) cat facts
# https://catfact.ninja/fact

from time import sleep
import requests
import random
import json

def getNewCatFact():
    r = requests.get("https://catfact.ninja/fact")
    if r.status_code != 200:
        print("Cat fact retrieval failed with code: ", r.status_code)

    parsed = json.loads(r.text)
    print(parsed['fact'])

if __name__ == "__main__":
    random.seed()
    number_of_cat_facts = random.randint(0,10)
    print("Getting ", number_of_cat_facts, " cat facts!")
    for i in range(0,number_of_cat_facts):
        getNewCatFact()
        sleep(3)
