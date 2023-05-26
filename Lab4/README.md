# Развертывание Threat intelligence Platform OpenCTI

## Цель работы

1. Освоить базовые подходы процессов Threat Intelligence
2. Освоить современные инструменты развертывания контейнеризованных приложений
3. Получить навыки поиска информации об угрозах ИБ

## ️Исходные данные

1. Ноутбук с ОС Windows 10.
2. Virtual Box с ОС Kali Linux.
3. Настроенные Docker и Elasticsearch.

## Ход выполнения работы

### Шаг 1

Для работы с ElasticSearch требуется увеличить размер виртуальной памяти системы:
```()
sudo sysctl -w vm.max_map_count=1048575
```

### Шаг 2

В новой директории создаем файл .env для хранения параметров окружения

### Шаг 3

В этой же директории находится файл docker-compose.yml

Запускаем приожение с помощью команды:
```()
sudo docker-compose up -d
```

### Шаг 4

Заходим в браузер и вводим в адресную строку: `localhost:8080`

Вводим логин и пароль из файла конфигурации окружения.

![image](https://github.com/Lektarin/threat-hunting/assets/87996224/a410ee17-7513-47c6-a320-10a9bee05998)

### Шаг 5

Попадаем на главную страницу

![image](https://github.com/Lektarin/threat-hunting/assets/87996224/11073354-63db-4cfb-b5dd-536f75026a1d)

### Шаг 6

Импортируем содержимое файла hosts.txt как индикаторы, используя модуль pycti.

``` python
from pycti import OpenCTIApiClient
from stix2 import TLP_GREEN
from datetime import datetime
from os import environ
from dotenv import load_dotenv

load_dotenv()
date = datetime.today().strftime("%Y-%m-%dT%H:%M:%SZ")
api_url = 'http://localhost:8080'
api_token = environ.get('OPENCTI_ADMIN_TOKEN')
client = OpenCTIApiClient(api_url, api_token)
TLP_GREEN_CTI = client.marking_definition.read(id=TLP_GREEN["id"])

with open('hosts', 'r') as file:
    domains = f.read().splitlines()
k = 1
for domain in domains:
    indicator = client.indicator.create(
    name="Malicious domain {}".format(k),
    description="domains",
    pattern_type="stix",
    pattern="[domain-name:value = '{}']".format(domain),
    x_opencti_main_observable_type="IPv4-Addr",
    valid_from=date,
    update=True,
    score=75,
    markingDefinitions=[TLP_GREEN_CTI["id"]],
    )
    print("Created indicator with ID:", indicator["id"])
    k += 1
```

Получаем список индикаторов нежелательных доменов:

![image](https://github.com/Lektarin/threat-hunting/assets/87996224/452b2340-ac00-4f88-830b-58bbb85bad51)


### Шаг 7

Преобразуем все индикаторы в Observables

### Шаг 8

Импортируем сетевой трафик из файла dns.log, который был получен в Лабораторной работе №2, в OpenCTI

![image](https://github.com/Lektarin/threat-hunting/assets/87996224/15c5fed8-e809-435b-8992-f6f2c464a3c3)

### Шаг 9

Переходим в раздел Analitics -> Report, чтобы посмотреть домены с нежелательным трафиком

![image](https://github.com/Lektarin/threat-hunting/assets/87996224/64661c2a-2fcf-48ac-a811-8acbf0c6feee)

Итого получилось 300 доменов.

## Оценка результата

С помощью платформы OpenCTI удалось проанализировать трафик на предмет перехода по нежелательным доменам.

## Выводы

Таким образом, были изучена платформа Threat Intelligence OpenCTI и возможности ее работы.
