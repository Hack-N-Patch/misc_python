# webdriver is the main player from selenium
from selenium import webdriver
# keys provides keyboard-like functions
from selenium.webdriver.common.keys import Keys
# these imports allow for selenium to wait for an expected condition before continuing
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

#create webdriver instance and tell it what browser to use
driver = webdriver.Firefox()

# navigate to the given URL
driver.get("https://www.pastebin.com")

# check that the page has Pastebin in the title
assert "Pastebin" in driver.title

# open sample1.txt
f = open("sample1.txt", "r")

# finding elements in the page, this time by name https://selenium-python.readthedocs.io/locating-elements.html#locating-elements
elem = driver.find_element_by_name("PostForm[text]")

# use imported keys to "type" text in element selected above
elem.clear()
elem.send_keys(f.read())
# submit is smart enough to know what form its submitting
elem.submit()

# wait for the url change before running assertion
WebDriverWait(driver, 360).until(EC.url_matches(r'https:\/\/pastebin\.com\/\S{8}'))
assert "Your guest paste has been posted." in driver.page_source
# print the url the file is posted to
print(driver.current_url)

# closing the webdriver
driver.close()
# close the file
f.close()
