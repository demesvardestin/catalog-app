### Catalog App
 
 Welcome to the Catalog App, a simple site displaying CRUD functionalities as
 well as basic third-party authentication with OAuth2. The app was built with
 Flask, SQL, Javascript and a few 3rd Party APIs.

#### Installation

 To run this app, you need to have a vm running on your OS, such as Vagrant.
 Download this project into your machine, then cd into its directory. It contains
 the vagrantfile. After cd'ing into your vagrantfile location, make sure the vm
 isrunning with the

```
vagrant up
```

 command. Then log in with 

```
vagrant ssh
```

 Then run

```
python catalog.py
```

 Once your server is up and running, go to your favorite browser, and type
 
 ```
 localhost:5000
 ```
 
 to boot up the app. From there, you can add categories, add items, or either
 update or delete them. You will need to be logged in before being able to
 perform those actions. Since this application is still in test mode, you will
 may use this facebook test account to authenticate:
 
 username: destinglobalholdings@gmail.com
 password: Knowledge1
