#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <map>

using namespace std;
int id_last_user = 0, id_last_question = 0;
struct Questions{
    string question_line, answer_line = "NOT Answered YET";
    int id = ++id_last_question;
};
struct UserInfo{
    string name, username, password, email;
    int id = ++id_last_user;
    vector<Questions> questions_from_user, questions_to_user;
    void signUp_operation(){
        cout << "Enter your name: ";
        getline(cin, name);
        cout << "Enter your email address: ";
        getline(cin, email);
        cout << "Enter your username: ";
        getline(cin, username);
        cout << "Enter your password: ";
        getline(cin, password);
        cout << endl;
        filestream_operation();
    }
    void filestream_operation(){
        fstream signUp_stream;
        signUp_stream.open("users.txt", ios::out | ios::in | ios::app);
        signUp_stream << name << " " << username << " " << email << " " << password << " " << id << endl;
        signUp_stream.close();
    }
};
struct Ask_Me_System{
 vector<UserInfo> users;
 void get_database_user_info(){
    fstream get_stream;
    get_stream.open("users.txt", ios::out | ios::in | ios::app);
    string line;
    while(true){
        getline(get_stream, line);
        if(get_stream.eof()){
            break;
        }
        stringstream info_stream(line);
        string name, username, email, password, id;
        info_stream >> name >> username >> email >> password >> id;
        users.push_back(UserInfo{name, username, password, email, stoi(id)});
        id_last_user = users.back().id;
    }
    get_stream.close();
 }
 void print_users(){
    for(auto user : users){
        cout << user.name << " " << user.username << " " << user.email << " " << user.password << " " << user.id << endl;
    }
 }
 void signUp_operation(){
    UserInfo user_info;
    user_info.signUp_operation();
    users.push_back(user_info);
 }
 void ask_question_operation(){
    string get_id, qustion_line;
    cout << "Enter user ID or -1 to cancel: ";
    getline(cin, get_id);
    if(get_id == "-1"){
        return;
    } 
    int user_id = stoi(get_id);
    cout << "Enter question text: " ;
    cin >> qustion_line;
    for(auto user : users){
        if(user.id == user_id){
            user.questions_to_user.push_back(Questions{qustion_line, "NOT Answered YET"});
        }
    }
 }
 int  login_operation(){
    int user_index = 0;
    string username, password;
    cout << "Enter your username: ";
    getline(cin, username);
    cout << "Enter your password: ";
    getline(cin, password);
    cout << endl;
    for(auto user : users){
        if(user.username == username && user.password == password){
            cout << "Login successful" << endl << endl;
            return user_index;
        }
        user_index++;
    }
    cout << "Invalid username or password" << endl << endl;
    return -1;
 }    
 bool choises_checker(char min_number, char max_number, string choice){
    return choice.size() > 1 || choice[0] < min_number || choice[0] > max_number;
 }
 void geust_menu(){
    int flag = -1;
    while(flag == -1){
        cout << "GEUST_MENU\n\t1. Sign Up" << endl;
        cout << "\t2. Login" << endl;
        cout << "\t3. Quit" << endl;
        cout << "\tEnter your choice: ";
        string choice;
        getline(cin, choice);

        cout << endl;

        if(choice == ""){ // it prevent from getting the same menu twice 
            getline(cin, choice);
        }
        if(choises_checker('1', '3', choice)){ // check if user entered something else
            cout << "Invalid choice" << endl << endl;
            continue;
        }
        int num = stoi(choice);
        switch(num){
            case 1: signUp_operation(); break;
            case 2: flag = login_operation(); break;
            case 3: return;
            default: cout << "Invalid operation, please try again." << endl << endl; break;
        }
    }
    user_menu(flag);
 }
 void user_menu(int user_index) {
    while(true){
        cout << "MENU\n\t1. Print Question To Me" << endl;
        cout << "\t2. Print Question From Me" << endl;
        cout << "\t3. Answer Question" << endl;
        cout << "\t4. Delete Question" << endl;
        cout << "\t5. Ask Question" << endl;
        cout << "\t6. List System Users" << endl;
        cout << "\t7. Feed" << endl;
        cout << "\t8. Logout" << endl;
        cout << "\t9. Quit" << endl;
        cout << "\tEnter your choice: ";
        string choice;
        getline(cin, choice);
        cout << endl;
        if(choice == ""){ // it prevent from getting the same menu twice 
            getline(cin, choice);
        }
        if(choises_checker('1', '9', choice)){ // check if user entered something else
            cout << "Invalid choice" << endl << endl;
            continue;
        }
        int num = stoi(choice);
        switch(num){
            case 1: break;
            case 2: break;
            case 5: ask_question_operation(); break;
            case 8: geust_menu(); return;
            case 9: return;
            default: cout << "Invalid operation, please try again." << endl << endl; break;
        }
    }
 }
 };
int main() {
    Ask_Me_System Askme1;

    Askme1.get_database_user_info(); 
    // Askme1.print_users();
    Askme1.geust_menu();

    return 0;
}