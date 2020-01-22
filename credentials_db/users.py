import string
import random

f_names = [
    "Joao",
    "Maria",
    "Rodrigo",
    "Matilde",
    "Francisco",
    "Leonor",
    "Diogo",
    "Sofia",
    "Vasco",
]

l_names = [
    "Silva",
    "Vasconcelos",
    "Ramos",
    "Bastos",
    "Mendes",
    "Almeida",
    "Andrade",
    "Oliveira",
]

permissions = ["-", "t"]


def gen_random_string(str_length=10):
    letters = string.ascii_letters + string.digits + "!#$%&'()*+,-./:<=>?@[\]^_`{|}~"
    return "".join(random.choice(letters) for i in range(str_length))


def generate_credentials(c):
    fname, lname = random.choice(f_names), random.choice(l_names)
    return (fname.lower() + lname.lower() + str(c) + "@ua.pt"), gen_random_string(20)


def main():
    with open("users.csv", "w") as f:
        f.write("Username;Password;;Permissions\n")
        for i in range(10):
            email, pwd = generate_credentials(i)
            f.write(f"{email};{pwd};;{random.choice(permissions)}\n")


if __name__ == "__main__":
    main()
