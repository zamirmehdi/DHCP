import Server


def server_terminal_handler():
    while True:
        command = input()
        if command == 'sh clients' or 'show clients':
            print(Server.clients_list)
        if command == 'terminate':
            break


server_terminal_handler()
