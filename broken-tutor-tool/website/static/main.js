var main = document.querySelector("main");
var login = document.querySelector("#login-page");
var register = document.querySelector("#register-page");
var resetpw = document.querySelector("#resetpw-page");
var profile = document.querySelector("#profile-page");
var courses = document.querySelector("#courses-page");
var apply = document.querySelector("#apply-page");
var applications = document.querySelector("#applications-page");
var application = document.querySelector("#application-page");
var error_popup = document.querySelector("#error-popup");
var success_popup = document.querySelector("#success-popup");
var navbar_user = document.querySelector("#navbar-user");
var navbar_supervisor = document.querySelector("#navbar-supervisor");

const error = (msg) => {
    var clone = error_popup.content.cloneNode(true);
    clone.querySelector("strong").textContent = msg;
    main.prepend(clone);
}

const success = (msg) => {
    var clone = error_popup.content.cloneNode(true);
    clone.querySelector("strong").textContent = msg;
    main.prepend(clone);
}

const show_register = (ctx, n) => {
    if (ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = register.innerHTML;

	document.querySelector("main form").addEventListener("submit", (e) => {
		e.preventDefault();
		var data = {};
		var formData = new FormData(e.target);
		formData.forEach((value, key) => data[key] = value);
        axios.post("/api/register", data)
			.then(resp => {
                var data = resp.data;
                if (data.status === "error") {
                    error(data.error);
                    return;
                }
                ctx.queuedPopup = "test";
                page("/");
            })
	});
}

const show_login = (ctx, n) => {
    if (ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = login.innerHTML;
	document.querySelector("main form").addEventListener("submit", (e) => {
		e.preventDefault();
		var data = {};
		var formData = new FormData(e.target);
		formData.forEach((value, key) => data[key] = value);
        axios.post("/api/login", data)
			.then(resp => {
                var data = resp.data;
                if (data.status === "error") {
                    error(data.error);
                    return;
                }
                var token = data.token;
                window.sessionStorage.token = token;
                page("/");
            })
	});
}

const show_resetpw = (ctx, n) => {
    if (ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = resetpw.innerHTML;

	document.querySelector("main form").addEventListener("submit", (e) => {
		e.preventDefault();
		var data = {};
		var formData = new FormData(e.target);
		formData.forEach((value, key) => data[key] = value);
        axios.post("/api/resetpw", data)
			.then(resp => {
                var data = resp.data;
                if (data.status === "error") {
                    error(data.error);
                    return;
                }
                page("/");
            })
	});
}

const show_logout = (ctx, n) => {
    delete ctx.user;
    delete axios.defaults.headers.common["Authorization"];
    delete window.sessionStorage.token;
    
    page("/");
}

const show_profile = (ctx, n) => {
    main.innerHTML = profile.innerHTML;
    axios.get("/api/my-profile")
    .then(resp => {
        var data = resp.data;
        if (data.status === "error") {
            error(data.error);
            return;
        }
        // TODO - this gives error if debug profile
        var profile = JSON.parse(data.profile);
        main.querySelector("#profile-title").textContent = "Profile of " + profile.firstname + " " + profile.lastname;
        Object.keys(profile).forEach((key, index) => {
            var element = main.querySelector('input[name="' + key + '"]');
            if (element) {
                element.value = profile[key];
            }
        });
    });

    main.querySelector("button").addEventListener("click", (e) => {
        var file = main.querySelector("#cv").files[0];
        var formData = new FormData;
        formData.append('cv', file);

        axios.put('/api/cv', formData, { headers: { 'Content-Type': 'multipart/form-data'} })
        .then((resp) => {
            var data = resp.data;
            if (data.status === "error") {
                error(data.error);
                return;
            }
            success("CV successfully uploaded!");
            page('/');
        }).catch(err => {
            error("Could not upload CV, file too large!");
            return;
        });
    });
}

const show_apply = (ctx, n) => {
    if (!ctx.user) {
        page("/");
        return;
    }

	main.innerHTML = apply.innerHTML;
    main.querySelector("h1").textContent = "Application for " + ctx.params.id

    axios.get("/api/course/" + ctx.params.id)
    .then(resp => {
        var data = resp.data;
        if (data.status === "error") {
            error(data.error);
            return;
        }

        main.querySelector("p").textContent = data.course.requirements;
    });

	document.querySelector("main form").addEventListener("submit", (e) => {
		e.preventDefault();

        axios.get("/api/cv")
        .then(resp => {
            var data = resp.data;
            if (data.status === "error") {
                cv_error = data.error;
                error(data.error);
                return;
            }

            var data = {
                'courseId': ctx.params.id,
                'cvToken': data.token,
                'grade': e.target.grade.value,
                'applicationText': e.target.applicationText.value,
            };

            var formData = new FormData(e.target);
            formData.forEach((value, key) => data[key] = value);
            axios.post("/api/apply", data)
            .then(resp => {
                var data = resp.data;
                if (data.status === "error") {
                    error(data.error);
                    return;
                }
                success("Application submitted!");
                page("/");
            });
        });
	});
}

const show_courses = (ctx, n) => {
    if (!ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = courses.innerHTML;
    
    axios.get("/api/courses")
    .then(resp => {
        var data = resp.data;
        if (data.status === "error") {
            error(data.error);
            return;
        }
        var course_body = main.querySelector("tbody");
        data.courses.forEach((course) => {
            if (!course.active) {
                return;
            }
            let row = course_body.insertRow();
            let id = row.insertCell();
            id.innerHTML = course.id;
            let name = row.insertCell();
            name.innerHTML = course.name;
            //let requirements = row.insertCell();
            //requirements.innerHTML = "Dummy requirements";
            let apply = row.insertCell();
            apply.innerHTML = '<a class="btn btn-primary" href="/courses/' + course.id + '/apply">Apply</a>';
        });
        //var profile = JSON.parse(data.profile);
        //main.querySelector("#profile-title").textContent = "Profile of " + profile.firstname + " " + profile.lastname;
        //Object.keys(profile).forEach((key, index) => {
        //    var element = main.querySelector('input[name="' + key + '"]');
        //    if (element) {
        //        element.value = profile[key];
        //    }
        //});
    });
}

const show_application = (ctx, n) => {
    if (!ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = application.innerHTML;

    axios.get("/api/application/" + ctx.params.id)
    .then(resp => {
        var data = resp.data;
        if (data.status === "error") {
            error(data.error);
            return;
        }

        main.querySelector("h1").innerHTML = "Application by " + data.application.email;
        main.querySelector("p").innerHTML = data.application.application;
    });
}

const show_applications = (ctx, n) => {
    if (!ctx.user) {
        page("/");
        return;
    }
	main.innerHTML = applications.innerHTML;
    
    axios.get("/api/applications")
    .then(resp => {
        var data = resp.data;
        if (data.status === "error") {
            error(data.error);
            return;
        }

        var applications_body = main.querySelector("tbody");
        data.applications.forEach((application) => {
            let row = applications_body.insertRow();
            let course = row.insertCell();
            course.innerHTML = application.course;
            let applicant_email = row.insertCell();
            applicant_email.innerHTML = application.email;
            let applicant_grade = row.insertCell();
            applicant_grade.innerHTML = application.grade;
            let application_text = row.insertCell();
            application_text.innerHTML = application.application;
            //let apply = row.insertCell();
            //apply.innerHTML = '<a class="btn btn-primary" href="/courses/' + course.id + '/apply">Apply</a>';
        });
        //var profile = JSON.parse(data.profile);
        //main.querySelector("#profile-title").textContent = "Profile of " + profile.firstname + " " + profile.lastname;
        //Object.keys(profile).forEach((key, index) => {
        //    var element = main.querySelector('input[name="' + key + '"]');
        //    if (element) {
        //        element.value = profile[key];
        //    }
        //});
    });
}

const show_overview = (ctx, n) => {
    if (ctx.user) {
        show_profile(ctx, n);
    } else {
        show_login(ctx, n);
    }
}

const load_user = (ctx, n) => {
    navbar_user.classList.remove('navbar-collapse');
    navbar_supervisor.classList.remove('navbar-collapse');
    if (window.sessionStorage.token) {
        axios.defaults.headers.common["Authorization"] = "Bearer " + window.sessionStorage.token;
        var decoded_token = JSON.parse(atob(window.sessionStorage.token.split('.')[1]));
        ctx.user = {"email": decoded_token.sub, "role": decoded_token.auth};
        if (ctx.user.role == "user") {
            navbar_user.classList.add('navbar-collapse');
        } else if (ctx.user.role === "supervisor") {
            navbar_supervisor.classList.add('navbar-collapse');
        }
        n();
    } else {
        n();
    }
}


// Shamelessly stolen/adapted from https://stackoverflow.com/questions/9142527/can-you-require-two-form-fields-to-match-with-html5
const checkpw = (input) => {
	if (input.value != document.querySelector("input[name='password']").value) {
		input.setCustomValidity('Password Must be Matching.');
	} else {
		// input is valid -- reset the error message
		input.setCustomValidity('');
	}
}

page('/*', load_user);
page('/', show_overview);
page('/login', show_login);
page('/logout', show_logout);
page('/register', show_register);
page('/resetpw', show_resetpw);
page('/profile', show_profile);
page('/courses', show_courses);
page('/courses/:id/apply', show_apply);
page('/applications', show_applications);
page('/application/:id', show_application);
page();
