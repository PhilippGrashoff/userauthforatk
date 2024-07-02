# userauthforatk - Beta

## Motivation
atk4/login is an existing repository to handle user authentication, but it carries a lot of UI code.
IMHO, user authentication has nothing to do with UI per se.

I need the logged-in user a lot in data layer to check sufficient rights for an action, audit changes made by users and so on.
The normal atk4\login way is to attach an `Auth` instance to Atk4\Ui\App, which then somehow needs to be passed down to data level if it should be used there.
As I split the code of my Application into several "data" and "ui" repositories, this way would require to widely use Atk4\Ui\App in data layer.
This repo aims to make the logged-in user available independently of UI.

## Current implementation, possible improvements etc
### Auth as Singleton
At first, all Auth actions (login, logout, get logged-in user) were implemented as static methods, such as `Auth::getUser($somePersistence)`. But this comes along with a major problem:
ATK models cannot be serialized - so only the field values of the logged-in user can be stored in Session. When using `Auth::getUser()` in several places, each call would create a new instance of the logged in user. This is not only bad from a performance POV.

The only solution I could think of was to use a singleton, as adding some dependency injection deep inside atk4\data seemed impossible at first glance. 
Some singleton "getter" for the logged-in user could have been implemented, but as Auth class is very small, it seemed less overhead to implement the whole Auth class as Singleton.
While the code isn't perfectly nice as it gets a bit longer (`Auth::getInstance()->getUser($somePersistence)`), it solves the issue of possibly having multiple instances for the logged-in user.

### Coupling to User Model
A basic User model comes with this repo. However, this Auth can be used with any User class as its independent of the User class.
This was achieved by moving the responsibility for successful login handling, failed login handling and before login handling (too many failed logins already?) to user model.
Generally, this responsibility is something that can be well put into Auth, but this also means that Auth needs to be aware
of the User classes capabilities.

In the current implementation, Auth only calls hooks in the user Model, so Auth does not need any knowledge of the User class. 
Hence, the User class can be easily exchanged.

### No usage of atk Session handling
At the moment, this repo does not use Atk session handling, as I only needed the minimal functionality of storing the logged-in User data in the Session. However, the normal Atk Session Handler could be easily used.

### (Impossible) configuration of Auth
One thing I do not really like is that Auth is not configurable in the current implementation. If you want to use a different User class than the provided one,
you will have to create a new Auth class which extends this Auth, just overwriting the `$userModel` property.
