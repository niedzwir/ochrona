document.addEventListener('DOMContentLoaded', function (event) {

    const GET = "GET";
    const POST = "POST";

    const LOGIN_FIELD_ID = "login";
	

    var HTTP_STATUS = {OK: 200, CREATED: 201, NOT_FOUND: 404};

    let registrationForm = document.getElementById("registration-form");

    registrationForm.addEventListener("submit", function (event) {
        event.preventDefault();

        console.log("Form submission");

		removeLoginWarningMessage("mail error");
        removeLoginWarningMessage("login error");
        removeLoginWarningMessage("password error");
		removeLoginWarningMessage("2password error");

		let bool_loginok = loginok();
		let bool_passok = passok();
		let bool_mailok = mailok();

		let send = false;
		if(bool_loginok && bool_passok && bool_mailok){
			send = true;
		}

	
		if(send == true){

			formData = new FormData();
			formData.set("login", document.getElementById("login").value);
			formData.set("password", document.getElementById("password").value);
			formData.set("repeatpassword", document.getElementById("repeat-password").value);
			formData.set("mail", document.getElementById("mail").value);
			
			submitRegisterForm(formData);
			
			console.log(send);
		}
		else{
			console.log(send);
		}
    });
	
	function removeLoginWarningMessage(warningElemId) {
        let warningElem = document.getElementById(warningElemId);

        if (warningElem !== null) {
            warningElem.remove();
        }
    }
	function passwordValidation(passwor, rePassword){
        var valid = true;
        if(passwor.length == 0 || rePassword.length == 0){
            valid = false;
        }
        else if (passwor.length < 8){
            valid = false;
        }
        else if (!(/^[a-zA-Z0-9\!\@\#\$\%\^\&\*]+$/.test(passwor))){
            valid = false;
        }
        else if(!(/[a-z]+/.test(passwor))){
            valid = false;
        }
        else if(!(/[A-Z]+/.test(passwor))){
            valid = false;
        }
        else if(!(/[0-9]+/.test(passwor))){
            valid = false;
        }
        else if(!(/[\!\@\#\$\%\^\&\*]+/.test(passwor))){
            valid = false;
        }
        if (passwor != rePassword){
			appendAfterElem("repeat-password", prepareLoginWarningElem("2password error", "hasła niezgodne"));
            valid = false;
        }

        return valid;

    }
	function mailok(){
		let mail = document.getElementById("mail").value;
		let ok = true;
		if(mail.length == 0){
            ok = false;
        }
        const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        if( re.test(String(mail).toLowerCase()) == false){
            ok = false
        }
		if(!(ok)){
			appendAfterElem("mail", prepareLoginWarningElem("mail error", "nieprawidłowy mail"));
		}
		return ok;
	}
	function passok(){
        let pass = document.getElementById("password").value;
        alert("entropia: " + entropy(pass));
		let pass2 = document.getElementById("repeat-password").value;
		let ok = passwordValidation(pass, pass2);
		
		if(!(ok)){
			appendAfterElem("password", prepareLoginWarningElem("password error", "nieprawidłowe hasło"));
		}
		
		return ok;
	}
	function loginok(){
		let login = document.getElementById("login").value;		
		let ok = true;

        if(login.length < 5){
            ok = false;
        }

		if(!(/^[a-zA-Z]+$/.test(login))){
			ok = false;
		}

		if(!(ok)){
			appendAfterElem("login", prepareLoginWarningElem("login error", "nieprawidłowy login"));
		}
		return ok;
		

	}
	
	
	function appendAfterElem(currentElemId, newElem) {
        let currentElem = document.getElementById(currentElemId);
        currentElem.insertAdjacentElement('afterend', newElem);
    }
	
	function prepareLoginWarningElem(newElemId, message) {
        let warningField = document.getElementById(newElemId);

        if (warningField === null) {
            let textMessage = document.createTextNode(message);
            warningField = document.createElement('span');

            warningField.setAttribute("id", newElemId);
            warningField.className = "warning-field";
            warningField.appendChild(textMessage);
        }
        return warningField;
	}
	const URL = "https://localhost:8090/";
	function submitRegisterForm(formData) {
        let registerUrl = URL + "register/";

        let registerParams = {
            method: POST,
            body: formData,
            redirect: "follow"
        };

		fetch(registerUrl, registerParams)
				.then(response => checkResponse(response))
				.then(response => console.log(response))
                .catch(err => {
                    console.log("Caught error: " + err);
				});
	}

	function checkResponse(response){
		console.log(response);
        console.log(status);
		if(response.status == 200){
			alert("zarejestrowano pomyślnie");
		}
		else{
			alert("login zajęty/nieprawidłowy email");
		}
    }
    
    function entropy(password){
        var stat = {};
        for (c in password){
            var m = c;
            if (m in stat){
                stat[m] += 1;
            }
            else{
                stat[m] = 1;
            }              
            var H = 0.0;
            var pi;
            for (i in stat){
                pi = stat[i]/password.length;
                H -= pi*Math.log2(pi);
            }           
        }           
        return H;
    }
    
	
	function getRegisterResponseData(response) {
        let status = response.status;

        if (status === HTTP_STATUS.OK || status === HTTP_STATUS.CREATED) {
            return response.json();
        } else {
            console.error("Response status code: " + response.status);
            throw "Unexpected response status: " + response.status;
        }
	}
	
	function displayInConsoleCorrectResponse(correctResponse) {
        let status = correctResponse.registration_status;

        console.log("Status: " + status);

        if (status !== "OK") {
            console.log("Errors: " + correctResponse.errors);
        }
    }

});