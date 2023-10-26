# Import necessary libraries
import csv  # For working with CSV files
from faker import Faker  # For generating fake data
import tkinter as tk  # For creating a GUI using Tkinter

# Define a function to get user input
def get_Values():
    global file_name, number_of_rows, error_deticat
    file_name = entry1.get()  # Get the file name from the user
    number_of_rows = entry2.get()  # Get the number of rows from the user
    if not (file_name.isalpha()) or not (number_of_rows.isnumeric()):
        # Check if the input is valid (file name contains alphabetic characters, number of rows is numeric)
        error_label.config(text="INVALID INPUT.", fg="red")  # Show an error message in red
        error_deticat = True  # Set an error flag to True if there's an error
    else:
        error_deticat = False  # Clear the error flag if there's no error
        root.destroy()  # Close the Tkinter window

# Create the main Tkinter window
root = tk.Tk()
root.title("Faker Data Generator")

# Set the size of the window (width x height)
root.geometry("300x200")

# Calculate the screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the x and y coordinates for the center of the screen
x = (screen_width - root.winfo_reqwidth()) // 2
y = (screen_height - root.winfo_reqheight()) // 2

# Set the form to appear in the center of the screen
root.geometry("+{}+{}".format(x, y))

# Create a frame to hold the input fields
frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

# Create labels and input fields for file name and number of rows
label1 = tk.Label(root, text="Enter file name")
label1.pack()
entry1 = tk.Entry(root)
entry1.pack()

# Create an error label to display validation errors
error_label = tk.Label(frame, text="", fg="red")
error_label.pack(anchor="w", padx=5, pady=5)

label2 = tk.Label(root, text="Enter the number of rows")
label2.pack()
entry2 = tk.Entry(root)
entry2.pack()

# Create a button to trigger data generation
submit_button = tk.Button(root, text="Generate", command=get_Values)
submit_button.pack()

# Create a frame to hold the statement label
frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

# Create a statement label
statement_label = tk.Label(frame, text="This program made by Kero Nady")
statement_label.pack(side=tk.LEFT, anchor=tk.SW, padx=10, pady=10)

# Start the Tkinter main loop
root.mainloop()

# Initialize the Faker generator
faker = Faker()

# Define the keys (column names) for the CSV
"""
Note: There's alot of keys you can use by Faker package
like {'country', 'credit_card', 'company'}, "search on Faker methods"
"""
keys = ['id', 'name', 'country', 'job', 'email', 'phone']

# Create an empty list to store the data
data = []

# Define a function to create a CSV file
def csv_File_Create(file_name, number_of_rows):
    id = 1
    with open(file_name, 'w',newline='' ) as file:
        file_data = csv.DictWriter(file, fieldnames=keys)
        file_data.writeheader()
        for row in range(int(number_of_rows)):
            data_dict = {}
            data_dict['id'] = id
            data_dict['name'] = faker.name()
            data_dict['country'] = faker.country()
            data_dict['job'] = faker.job()
            data_dict['email'] = faker.free_email()
            data_dict['phone'] = faker.phone_number()
            data.append(data_dict)
            id += 1
        file_data.writerows(data)

# Check the error flag and create the CSV file if there are no errors
if error_deticat:
    pass
else:
    csv_File_Create(file_name + ".csv", number_of_rows)

# !if there are any errors please contact the author 'keropop024@gmail.com'
# !Copyright 2023 by Kyrillos Nady. All Rights Reserved.
