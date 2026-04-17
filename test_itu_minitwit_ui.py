"""
To run this test with a visible browser, the following dependencies have to be setup:

  * `pip install selenium`
  * `pip install pymongo`
  * `pip install pytest`
  * `wget https://github.com/mozilla/geckodriver/releases/download/v0.32.0/geckodriver-v0.32.0-linux64.tar.gz`
  * `tar xzvf geckodriver-v0.32.0-linux64.tar.gz`
  * After extraction, the downloaded artifact can be removed: `rm geckodriver-v0.32.0-linux64.tar.gz`

The application that it tests is the version of _ITU-MiniTwit_ that you got to know during the exercises on Docker:
https://github.com/itu-devops/flask-minitwit-mongodb/tree/Containerize (*OBS*: branch Containerize)

```bash
$ git clone https://github.com/HelgeCPH/flask-minitwit-mongodb.git
$ cd flask-minitwit-mongodb
$ git switch Containerize
```

After editing the `docker-compose.yml` file file where you replace `youruser` with your respective username, the
application can be started with `docker-compose up`.

Now, the test itself can be executed via: `pytest test_itu_minitwit_ui.py`.
"""

import os
import psycopg2
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options


GUI_URL = os.environ.get("GUI_URL", "http://web:3000/register")
DB_HOST = os.environ.get("POSTGRES_HOST", "database")
DB_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
DB_NAME = os.environ["POSTGRES_DB"]
DB_USER = os.environ["POSTGRES_USER"]
DB_PASS = os.environ["POSTGRES_PASSWORD"]



def _get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )

def _register_user_via_gui(driver, username, email, password):
    driver.get(GUI_URL)
    wait = WebDriverWait(driver, 5)
    wait.until(EC.presence_of_element_located((By.NAME, "username")))

    driver.find_element(By.NAME, "username").send_keys(username)
    driver.find_element(By.NAME, "email").send_keys(email)
    driver.find_element(By.NAME, "password").send_keys(password)
    driver.find_element(By.NAME, "password2").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()


def _get_user_by_name(name):
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = %s", (name,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

def _delete_user_by_name(name):
    conn = _get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = %s", (name,))
    conn.commit()
    cur.close()
    conn.close()


def test_register_user_via_gui():
    """
    This is a UI test. It only interacts with the UI that is rendered in the browser and checks that visual
    responses that users observe are displayed.
    """
    options = Options()
    options.add_argument("--headless")

    with webdriver.Firefox(options=options) as driver:
        _register_user_via_gui(driver, "testuser_ui", "testuser@example.com", "secure123")

        wait = WebDriverWait(driver, 5)
        wait.until(EC.url_contains("/login"))
        assert "/login" in driver.current_url

    _delete_user_by_name("testuser_ui")


def test_register_user_via_gui_and_check_db_entry():
    """E2E test: registers via UI and verifies the user exists in the database."""
    options = Options()
    options.add_argument("--headless")
    with webdriver.Firefox(options=options) as driver:
        assert _get_user_by_name("testuser_e2e") is None

        _register_user_via_gui(driver, "testuser_e2e", "e2e@example.com", "secure123")

        wait = WebDriverWait(driver, 5)
        wait.until(EC.url_contains("/login"))

        assert _get_user_by_name("testuser_e2e") is not None

    _delete_user_by_name("testuser_e2e")
