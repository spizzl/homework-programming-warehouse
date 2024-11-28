using warehouse;
using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Globalization;

namespace warehouse {

    class User {
        public enum UserRoles {
            Admin,
            Staff,
            Guest
        }
        public string Username;
        private String Password;
        public string FullName;
        public UserRoles Role;

        public User(string username, string password, string fullName, UserRoles role) {
            Username = username;
            Password = password;
            FullName = fullName;
            Role = role;
        }

        public String getpasswordhash() {
            return Password;
        }

        public void ShowUser() {
            Console.Write("Username: " + Username + "\t");
            Console.Write("Full Name: " + FullName + "\t");
            Console.Write("PasswordHash: " + Password + "\t");
            Console.Write("Role: " + Role + "\n");
        }

        public void changepassword() {
            Console.Write("[*] Password: ");
            String newpass = inputpassword();
            byte[] dings = gensalt();
            String hashedpasswd = HashPassword(newpass, dings);
            Password = hashedpasswd;
        }

        public Boolean Login(string passwordinput) {
            byte[] usersalt = new byte[16];
            byte[] userbytespass = Convert.FromBase64String(Password);
            Buffer.BlockCopy(userbytespass, 0, usersalt, 0, 16);
            String enteredPasswordHash = HashPassword(passwordinput, usersalt);
            return (enteredPasswordHash == Password);
        }

        public static String inputpassword() {
            String input = "";
            while (true) {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) {
                    break;
                } else if (key.Key == ConsoleKey.Backspace) {
                    if (input.Length > 0) {
                        input = input.Substring(0, input.Length - 1);
                        Console.Write("\b \b");
                    }
                    continue;
                } else {
                    Console.Write("X");
                }
                input += key.KeyChar;
            }
            Console.Write("\n");
            return input;
        }

        public static byte[] gensalt() {
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider()) {
                rng.GetBytes(salt);
            }
            return salt;
        }

        public static string HashPassword(string password, byte[] salt) {
            using (var sha256 = new SHA256Managed()) {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltedPassword = new byte[passwordBytes.Length + salt.Length];
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, passwordBytes.Length, salt.Length);
                byte[] hashedBytes = sha256.ComputeHash(saltedPassword);
                byte[] hashedPasswordWithSalt = new byte[hashedBytes.Length + salt.Length];
                Buffer.BlockCopy(salt, 0, hashedPasswordWithSalt, 0, salt.Length);
                Buffer.BlockCopy(hashedBytes, 0, hashedPasswordWithSalt, salt.Length, hashedBytes.Length);
                return Convert.ToBase64String(hashedPasswordWithSalt);
            }
        }
    }

    class Product {
        public enum Status {
            RefillNeeded,
            InStock,
            AwaitingShippment
        }

        public Status ProdcutStaus;
        public string Name;
        public float Price;
        public int Stock;
        public string Brand;

        public Product(string name, string brand, float price, int stock) {
            Name = name;
            Brand = brand;
            Price = price;
            Stock = stock;
            UpdateProductStatus();
        }

        void UpdateProductStatus() {
            if (Stock == 0) {
                ProdcutStaus = Status.AwaitingShippment;
            } else if (Stock < 10) {
                ProdcutStaus = Status.RefillNeeded;
            } else {
                ProdcutStaus = Status.InStock;
            }
        }
    }

    class MainClass {
        private static List<User> users = new List<User>();
        public static void Main(string[] args) {
            String userfilepath = "/home/fuzzywood/Documents/htw/programming/warehouse/users.csv";
            users = ReadUsersFromCsv(userfilepath);
            Boolean exit = false;
            User logged_in = new User("guest", "", "Guest User", User.UserRoles.Guest);;
            List<Product> products = new List<Product> {
                new Product("Toaster", "Simens", 1.99f, 100),
                new Product("Toaster", "Shingu", 0.99f, 150),
                new Product("Electric Toothbrush", "Panasonic", 1.49f, 200),
                new Product("Coffee Maker", "DeLonghi", 79.99f, 75),
                new Product("Laptop", "Dell", 999.99f, 20),
                new Product("Smartphone", "Apple", 799.99f, 15),
                new Product("Headphones", "Sony", 199.99f, 40),
                new Product("Smartwatch", "Garmin", 299.99f, 25),
                new Product("Tablet", "Samsung", 499.99f, 10)
            };
            Console.WriteLine("Welcome to the Warehouse Management System");
            Console.WriteLine("Type \'help\' for a list of commands");
            while (!exit) {
                Console.Write("[" + logged_in.Username + "]: ");
                string option = Console.ReadLine();
                switch (option, logged_in.Role) {
                    case ("register", User.UserRoles.Admin):
                    case ("r", User.UserRoles.Admin):
                        RegisterUser();
                        FlushUsers(userfilepath);
                        break;
                    case ("add", User.UserRoles.Staff):
                    case ("add", User.UserRoles.Admin):
                    case ("a", User.UserRoles.Staff):
                    case ("a", User.UserRoles.Admin):
                        addDialog();
                        break;
                    case ("exit", _):
                    case ("x", _):
                        exit = true;
                        break;
                    case ("show", User.UserRoles.Staff):
                    case ("show", User.UserRoles.Admin):
                    case ("s", User.UserRoles.Staff):
                    case ("s", User.UserRoles.Admin):
                        foreach (var i in products) {
                            Console.WriteLine("Name: " + i.Name + " Brand: " + i.Brand + " Price: " + i.Price +
                                              " Stock: " + i.Stock + " Status: " + i.ProdcutStaus);
                        }
                        break;
                    case ("login", _):
                    case ("l", _):
                        if (Login()) {
                            Console.WriteLine("[+] Suceessfully logged in as " + logged_in.Username);
                        } else {
                            Console.WriteLine("[-] Authentication failed");
                        }
                        break;
                    case ("help", _):
                    case ("h", _):
                        Console.WriteLine("(a)dd          Adds a new product");
                        Console.WriteLine("(r)egister     Register a new User");
                        Console.WriteLine("(s)how         List all products");
                        Console.WriteLine("(e)xit         Exit the program");
                        Console.WriteLine("(l)ogin        Login to the system");
                        Console.WriteLine("(u)sers        List all users");
                        Console.WriteLine("(d)eleteuser   Delete a user");
                        Console.WriteLine("(h)elp         Show this help message");
                        break;
                    case ("users", User.UserRoles.Admin):
                    case("u", User.UserRoles.Admin):
                        ShowUsers();
                        break;
                    case ("deleteuser", User.UserRoles.Admin):
                    case("d", User.UserRoles.Admin):
                        while (true) {
                            Console.Write("[*] Enter the index of the User to delete: (type ? for a overview) ");
                            String i = Console.ReadLine();
                            if (i == "?") {
                                ShowUsers();
                                continue;
                            }
                            int index = Convert.ToInt32(i);
                            if (index == 0)
                            {
                                Console.WriteLine("[-] Cannot delete the Admin User");
                                break;
                            }
                            try {
                                users.RemoveAt(index);
                                FlushUsers(userfilepath);
                                Console.WriteLine("[+] User deleted");
                                break;
                            } catch (Exception e) {
                                Console.WriteLine("[!] Invalid User");
                                continue;
                            }
                        }
                        break;
                    default:
                        Console.WriteLine("[-] Invalid option or insufficient permissions");
                        break;
                }
            }

            void ShowUsers() {
                int h = 0;
                foreach (User i in users) {
                    Console.Write("[" + Convert.ToString(h) + "]  ");
                    i.ShowUser();
                    h++;
                }
            }
            void RegisterUser() {
                Console.Write("[*] Username: ");
                string username = Console.ReadLine();
                Console.Write("[*] Full Name: ");
                string fullname = Console.ReadLine();
                string role;
                while (true) {
                    Console.Write("[*] Role: (? for overview) ");
                    role = Console.ReadLine();
                    if (role == "?") {
                        Console.WriteLine("Admin - Full access to the system");
                        Console.WriteLine("Staff - Limited access to the system");
                        Console.WriteLine("Guest - No access to the system");
                    } else if (role == "Admin" || role == "Staff" || role == "Guest") {
                        break;
                    } else {
                        Console.WriteLine("[!] Invalid Role");
                    }
                }
                User.UserRoles userrole;
                Enum.TryParse<User.UserRoles>(role, out userrole);
                User tmp = new User(username, "", fullname, userrole);
                tmp.changepassword();
                users.Add(tmp);
            }

            Boolean Login() {
                Console.Write("[*] Username: ");
                string username = Console.ReadLine();
                Console.Write("[*] Password: ");
                String input = User.inputpassword();
                foreach (var i in users) {
                    if (i.Username == username) {
                        if (i.Login(input)) {
                            logged_in = i;
                            return true;
                        }
                    }
                }
                return false;
            }

            void addDialog() {
                try {
                    Console.Write("Name of the Product: ");
                    string name = Console.ReadLine();
                    Console.Write("Brand of the Product: ");
                    string brand = Console.ReadLine();
                    Console.Write("Price of the Product: ");
                    float price = float.Parse(Console.ReadLine());
                    Console.Write("Stock of the Product: ");
                    int stock = int.Parse(Console.ReadLine());
                    products.Add(new Product(name, brand, price, stock));
                } catch (Exception e) {
                    Console.WriteLine("[!] Error: adding the Procut");
                }
            }

            void FlushUsers(String filepath) {
                try {
                    using (StreamWriter writer = new StreamWriter(filepath)) {
                        foreach (var user in users) {
                            writer.WriteLine($"{user.Username},{user.getpasswordhash()},{user.FullName},{user.Role}");
                        }
                    }
                } catch (Exception e) {
                    Console.WriteLine("[!] Error: Unable to write users to CSV file");
                }
            }

            List<User> ReadUsersFromCsv(string filePath) {
                List<User> userlist = new List<User>();
                try {
                    string[] lines = File.ReadAllLines(filePath);
                    foreach (string line in lines) {
                        string[] data = line.Split(',');
                        if (data.Length != 4) {
                            Console.WriteLine("[!] Error: Invalid CSV format");
                            return userlist;
                        } else {
                            User user = new User(data[0], data[1], data[2], (User.UserRoles)Enum.Parse(typeof(User.UserRoles), data[3]));
                            userlist.Add(user);
                        }
                    }
                } catch (Exception e) {
                    Console.WriteLine("[!]");
                }
                return userlist;
            }
        }
    }
}