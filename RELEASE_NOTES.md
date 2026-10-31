**The client is now international: English and Russian, and a choice of country for “sites of my country without the VPN”.**

- **Language.** The whole program, the messages and the tray menu are in English and Russian. A new installation takes the language of the system; you can change it at any time in the same dialog as the country (the “Country” button next to “Routing”). An existing installation stays in Russian until you change it.
- **Country.** The first start asks one thing: where you are (the country is suggested from your connection and the system settings). Sites of that country (banks, government services, local shops and services) then open without the VPN, and everything else goes through it. More than 80 countries; “None” sends everything through the VPN. The choice can be changed later with the “Country” button next to “Routing”. An existing installation keeps Russia.
- **How it works for other countries.** The sites are recognised by the country's domain ending and by the address lists of the sing-box project (they are downloaded at the first connection and refreshed from time to time). Russia, China and Iran also have site lists, because there the domain ending is not enough. Where there is a resolver of the country itself (Russia), it is used; elsewhere the system's.
- **Countries that block sites.** In Russia, Belarus, China, Iran and a few others “Fastest from the list” skips servers that exit in your own country: they cannot get around the blocking. In other countries all servers are used.
- **English everywhere else.** The README, the website and the issue forms are in English and Russian ([README in Russian](https://github.com/serafimbelskih32-source/windows-vpn-client/blob/main/README.ru.md)).

Still here from 1.4.0: servers with XHTTP, mKCP and similar transports (through Xray, which starts by itself), traffic left and expiry date, programs outside the VPN, pinned servers, start at login.

If you update from version 1.2.1 or older, the window “Failed to load Python DLL” may appear once: just start the program again, the update is already installed.

**Linux and macOS.** These versions are built and checked automatically on GitHub, but I could not run them on a real Linux or Mac computer. If something does not work, open an [Issue](https://github.com/serafimbelskih32-source/windows-vpn-client/issues) and attach the text from the “Log” section. The English texts were written without a native speaker's review: if a phrase reads oddly, tell us.

---

**Клиент стал международным: английский и русский языки и выбор страны для «сайты моей страны без VPN».**

- **Язык.** Вся программа, сообщения и меню в трее на английском и русском. Новая установка берёт язык системы; его можно сменить в любой момент там же, где страну (кнопка «Страна» рядом с «Маршрут»). Уже установленная программа остаётся на русском, пока ты не сменишь язык.
- **Страна.** При первом запуске программа спрашивает одно: где ты находишься (страна подсказывается по подключению и настройкам системы). Сайты этой страны (банки, госуслуги, местные магазины и сервисы) открываются без VPN, остальное идёт через него. Больше 80 стран; «Нигде» отправляет через VPN всё. Выбор можно поменять кнопкой «Страна» рядом с «Маршрут». Уже установленная программа остаётся с Россией.
- **Как это работает для других стран.** Сайты узнаются по доменному окончанию страны и по спискам адресов проекта sing-box (они скачиваются при первом подключении и время от времени обновляются). Для России, Китая и Ирана есть ещё и списки сайтов, потому что там одного окончания мало. Там, где есть собственный резолвер страны (Россия), используется он, в остальных случаях системный.
- **Страны, где блокируют сайты.** В России, Беларуси, Китае, Иране и ещё нескольких «Быстрейший из списка» не берёт серверы с выходом в твоей же стране: блокировки через них не обойти. В остальных странах используются все серверы.
- **Остальное тоже на двух языках.** README, сайт и формы для обращений на английском и русском ([README по-русски](https://github.com/serafimbelskih32-source/windows-vpn-client/blob/main/README.ru.md)).

Остаётся из 1.4.0: серверы XHTTP, mKCP и похожие (через Xray, он запускается сам), остаток трафика и срок подписки, программы мимо VPN, закреплённые серверы, автозапуск.

Если ты обновляешься с версии 1.2.1 или старше, окно «Failed to load Python DLL» может появиться один раз: тогда просто запусти программу заново, обновление уже установлено.

**Linux и macOS.** Эти версии собираются и проходят автоматические проверки на GitHub, но я не мог запустить их на настоящем компьютере с Linux или Mac. Если что-то работает не так, открой [Issue](https://github.com/serafimbelskih32-source/windows-vpn-client/issues) и приложи текст из раздела «Лог». Английские тексты писались без проверки носителем языка: если какая-то фраза звучит странно, расскажи.
