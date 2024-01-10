#!/bin/env python3
# -*- coding: utf-8 -*-
from ldap3 import Connection, Server, ALL, Tls, SUBTREE
import sys, logging, ssl, os
from dotenv import load_dotenv
import re
import shelve
import time

# проверяет, можно ли записать в файл логов. Если нет, она настраивает логирование в stderr. Это предотвращает прерывание скрипта из-за ошибок доступа к файлу логов.
def setup_logging(script_log_file, script_log_level, log_format, log_datefmt, log_encoding):
    try:
        if os.access(script_log_file, os.W_OK):
            logging.basicConfig(filename=script_log_file, level=script_log_level, format=log_format, datefmt=log_datefmt, encoding=log_encoding)
        else:
            logging.basicConfig(level=script_log_level, format=log_format, datefmt=log_datefmt)
            logging.warning("Logging to file is not possible. Logging to stderr instead.")
    except Exception as e:
        logging.basicConfig(level=script_log_level, format=log_format, datefmt=log_datefmt)
        logging.warning(f"Error setting up file logging: {e}. Logging to stderr instead.")

def format_username(username: str, ad_domain: str, ipa_domain: str) -> str:
    if '@dserver.cat' in username:
        return username.replace(ad_domain,'')
    elif '@kaff.cat' in username:
        return username.replace(ipa_domain, '')
    else:
        return username

# Функция соединения с АД по защищенному шифрованному соединению по 636 порту с использованием корневого сертификата домена.
# AD connect
def ad_connect(ad_user, ad_user_password, ad_kds, adca):
    tlset = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=adca)
    timeout = 10
    for ad_kd in ad_kds:
        try:
            server = Server(ad_kd, port=636, use_ssl=True, get_info=ALL, tls=tlset, connect_timeout=timeout)
            ad_connection = Connection(server, ad_user, ad_user_password, read_only=False, lazy=False)
            ad_connection.open()
            if ad_connection.bind():
                logging.info(f'==> AD_KD_Server {ad_kd} connect_status: {ad_connection.result}\n')
                return ad_connection
            else:
                logging.info(f'==> AD_KD_Server {ad_kd} bind_failed: {ad_connection.result}')
        except Exception as e:
            logging.info(f'==> AD_KD_Server {ad_kd} ERROR: {e}')
    logging.error(f'All AD server connections failed: {ad_kds}')
    sys.exit(1)
#  END Connect

def get_user_ad_key(ad_connection, ad_users_dn, username: str):
    search_filter = f'(sAMAccountName={username})'
    ad_connection.search(search_base=ad_users_dn, search_filter=search_filter, search_scope=SUBTREE,
                         attributes=['altSecurityIdentities'])
    if ad_connection.entries:
        user = ad_connection.entries[0]
        altSecurityIdentities = user.entry_attributes_as_dict['altSecurityIdentities']
        return altSecurityIdentities
    else:
        return None

# Получает ключи SSH пользователя из AD с кэшированием и истечением срока действия кэша.
def get_user_ad_key_with_expiry(ad_connection, ad_users_dn, username: str, cache_file, expiry):
    """
    :param ad_connection: соединение с Active Directory
    :param ad_users_dn: DN (Distinguished Name) для пользователей в AD
    :param username: имя пользователя
    :param cache_file: путь к файлу кэша
    :param expiry: время жизни кэша в секундах (по умолчанию 86400 секунд, т.е. 1 день)
    :return: SSH ключи пользователя или None
    """
    with shelve.open(cache_file) as cache:
        current_time = time.time()
        cached_data = cache.get(username)

        # Проверяем, есть ли данные в кэше и не истек ли их срок
        if cached_data and current_time - cached_data['timestamp'] < expiry:
#            print(f'Не истёк {expiry}')
            return cached_data['keys']

        # Если данных нет в кэше или истек срок, запрашиваем из AD
        search_filter = f'(sAMAccountName={username})'
        ad_connection.search(search_base=ad_users_dn, search_filter=search_filter, search_scope=SUBTREE,
                             attributes=['altSecurityIdentities'])
        if ad_connection.entries:
            user = ad_connection.entries[0]
            altSecurityIdentities = user.entry_attributes_as_dict['altSecurityIdentities']
            # Сохраняем результат в кэш с временной меткой
            cache[username] = {'keys': altSecurityIdentities, 'timestamp': current_time}
            return altSecurityIdentities
        else:
            return None

# Читаем локальные для хоста публичные ключи
def read_local_public_key(user: str):
    home_dir = f"/home/{user}"
    auth_keys_path = os.path.join(home_dir, ".ssh", "authorized_keys")

    if os.path.isfile(auth_keys_path):
        with open(auth_keys_path, 'r') as f:
            keys = f.readlines()
        return keys
    else:
        return None

# Главная программа
if __name__ == '__main__':

    # Попытка загрузить переменные окружения из файла .conf
    if not load_dotenv('get_ssh_key.conf'):
        logging.error("Конфигурационный файл не найден.")
        sys.exit(1)

    # Получение настроек из конфигурационного файла:
    ipaservers = os.getenv('ipa_server')
    if ipaservers is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_server')
        sys.exit(1)
    # Разделение строки на список серверов с использованием регулярных выражений
    ipa_servers = re.split(r'\s*,\s*', ipaservers.strip())

    ipaver_ssl = os.getenv('ipa_server_ca')
    if ipaver_ssl is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_server_ca')
        sys.exit(1)

    ipausername = os.getenv('ipa_user_admin')
    if ipausername is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_user_admin')
        sys.exit(1)

    ipapassword = os.getenv('ipa_user_admin_passwd')
    if ipapassword is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_user_admin_passwd')
        sys.exit(1)

    ad_groups_dn = os.getenv('ad_groups_dn')
    if ad_groups_dn is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_groups_dn')
        sys.exit(1)

    ad_users_dn = os.getenv('ad_users_dn')
    if ad_users_dn is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_users_dn')
        sys.exit(1)

    ad_kd = os.getenv('ad_server')
    if ad_kd is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_server')
        sys.exit(1)
    # Разделение строки на список серверов с использованием регулярных выражений
    ad_kds = re.split(r'\s*,\s*', ad_kd.strip())

    adca = os.getenv('ad_ca_sert')
    if adca is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_ca_sert')
        sys.exit(1)

    ad_user = os.getenv('ad_user')
    if ad_user is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_user')
        sys.exit(1)

    ad_user_password = os.getenv('ad_user_password')
    if ad_user_password is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_user_password')
        sys.exit(1)

    script_log_file = os.getenv('script_log_file')
    if script_log_file is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: script_log_file')
        sys.exit(1)

    script_log_level = os.getenv('script_log_level')
    if script_log_level is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: script_log_level')
        sys.exit(1)

    log_format = os.getenv('log_format')
    if log_format is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: log_format')
        sys.exit(1)

    log_datefmt = os.getenv('log_datefmt')
    if log_datefmt is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: log_datefmt')
        sys.exit(1)

    log_encoding = os.getenv('log_encoding')
    if log_encoding is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: log_encoding')
        sys.exit(1)

    ad_domain = os.getenv('ad_domain')
    if ad_domain is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ad_domain')
        sys.exit(1)

    ipa_domain = os.getenv('ipa_domain')
    if ipa_domain is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: ipa_domain')
        sys.exit(1)

    cache_file = os.getenv('cache_file')
    if cache_file is None:
        logging.error(f'Не удалось загрузить из конфигурационного файла значение: cache_file')
        sys.exit(1)

    # Значение по умолчанию для expiry
    DEFAULT_EXPIRY = 86400  # Например, 1 день = 86400 секунд
    expiry = os.getenv('expiry', DEFAULT_EXPIRY)
    try:
        expiry = int(expiry)
    except ValueError:
        logging.error(f"Значение 'expiry' должно быть целым числом. Используется значение по умолчанию: {DEFAULT_EXPIRY}")
        expiry = DEFAULT_EXPIRY

    # Получим числовое значение уровня логирования
    level = logging.getLevelName(script_log_level)
    # Настраиваем логгирование всех действий скрипта в файл
    #logging.basicConfig(filename=script_log_file, level=level, format=log_format, datefmt=log_datefmt)
    setup_logging(os.getenv('script_log_file'), logging.getLevelName(os.getenv('script_log_level')),
                 os.getenv('log_format'), os.getenv('log_datefmt'), os.getenv('log_encoding'))

    # define a Handler which writes INFO messages or higher to the sys.stderr
    # Здесь настройка вывода выхлопа информационных сообщений скрипта еще и в консоль помимо записи лога файла
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # add the handler to the root logger
    logging.getLogger('').addHandler(console)

    # Соединяемся с АД согласно полученным кредам
    ad_connection = ad_connect(ad_user, ad_user_password, ad_kds, adca)

    if len(sys.argv) > 1:  # проверяем, есть ли аргументы командной строки
        formatted_username = format_username(sys.argv[1], ad_domain, ipa_domain)

# Сначала смотрим есть ли локальный ключ или ключи для данного пользователя, так как это быстрее и приоритетнее при заходе под локальной УЗ
        local_keys = read_local_public_key(formatted_username)
        if local_keys:
            for key in local_keys:
                print(key, end="")
            sys.exit(0)

# Если же локальной УЗ нет, проверяем есть ли ключ для пользователя из АД
        user_ad_key = get_user_ad_key_with_expiry(ad_connection, ad_users_dn, formatted_username, cache_file, expiry)
        if user_ad_key:  # проверка, что dn_user не пустой и не None
            print(''.join(user_ad_key))
            ad_connection.unbind()
            sys.exit(0)


# END - закрываем соединение с АД и FreeIPA
    ad_connection.unbind()
