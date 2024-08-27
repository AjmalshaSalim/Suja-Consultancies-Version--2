$(document).ready(function(){
    $("#edit-prfl-btn").click(function(){
        $("#name-update").show();
    });

    $("#close-btn").click(function(){
        $("#name-update").hide();
    });
    $("#pic").focus(function(){
        $(this).attr("type","file");
    });
    $("#update-btn-name").click(function(event){
        let profilepic= $("#pic").val();
        let firstname = $("#firstname").val();
        let lastname = $("#lastname").val();
        let currentposition = $("#current-position").val();
        let currentcompany = $("#current-company").val();
        if(firstname === "" || lastname === "" || currentposition === "" || currentcompany === "" || profilepic==""){
            if(profilepic == ""){
                $("#error-notification-pic").show();
            } else {
                $("#error-notification-pic").hide();
                event.preventDefault();
            }
            if(firstname === ""){
                $("#error-notification-frst-name").show();
            } else {
             
                $("#error-notification-frst-name").hide();
                event.preventDefault();
            }
            if(lastname === ""){
                $("#error-notification-last-name").show();
            } else {
                $("#error-notification-last-name").hide();
                event.preventDefault();
            }
            if(currentposition === ""){
                $("#error-notification-position").show();
            }
            else {
                $("#error-notification-position").hide();
                event.preventDefault();
            }
            if(currentcompany === ""){
                $("#error-notification-company").show();
            } else {
                $("#error-notification-company").hide();
                event.preventDefault();
            }
         } 
        //else {
        //     $("#prfl-firstname").text(firstname)
        //     $("#prfl-lastname").text(lastname)
        //     $("#prfl-company").text(currentcompany)
        //     $("#prfl-position").text(currentposition)
        //     $("#prfl-pic").attr("src", profilepic);
        //     $("#name-update").hide();
        // }
    });
});
$(document).ready(function(){
    $("#edit-contact-btn").click(function(){
        $("#contact-update").show();
    });
    $("#contact-close-btn").click(function(){
        $("#contact-update").hide();
    });
    $("#update-btn-contact").click(function(event){
        let number= $("#number").val();
        let location = $("#location").val();
        let email = $("#email").val();
        if(number === "" || location === "" || email === ""){
            if(number == ""){
                $("#error-notification-number").show();
            } else {
                $("#error-notification-number").hide();
                event.preventDefault();
            }
            if(location === ""){
                $("#error-notification-location").show();
            } else {
             
                $("#error-notification-location").hide();
                event.preventDefault();
            }
            if(email === ""){
                $("#error-notification-email").show();
            } else {
                $("#error-notification-email").hide();
                event.preventDefault();
            }
        } 
        // else {
        //     $("#prfl-number").text(number)
        //     $("#prfl-location").text(location)
        //     $("#prfl-email").text(email)
        //     $("#contact-update").hide();
        // }
    });
});
$(document).ready(function(){
    $(".education-edit-btn").click(function(){
        $("#education-update").show();
    });
    $("#education-close-btn").click(function(){
        $("#education-update").hide();
    });
    // $(".education-delete-btn").click(function(){
    //     $(this).closest(".eachrow").remove();
    // });
   
    

    $("#update-btn-education").click(function(event){
        let graduation= $("#qulification").val();
        let university = $("#university").val();
        let branch = $("#stream").val();
        let cgpa = $("#percentage").val();
        if(graduation === "" || university === "" || branch === ""|| cgpa=== ""){
            if(graduation == ""){
                $("#error-notification-qualification").show();
            } else {
                $("#error-notification-qualification").hide();
                event.preventDefault();
            }
            if(university === ""){
                $("#error-notification-university").show();
            } else {
             
                $("#error-notification-university").hide();
                event.preventDefault();
            }
            if(branch === ""){
                $("#error-notification-stream").show();
            } else {
                $("#error-notification-stream").hide();
                event.preventDefault();
            }
            if(cgpa === ""){
                $("#error-notification-percentage").show();
            } else {
                $("#error-notification-percentage").hide();
                event.preventDefault();
            }
        } 
        // else {
        //     $("#prfl-header").text(graduation)
        //     $("#prfl-univercity").text(university)
        //     $("#prfl-branch").text(branch)
        //     $("#prfl-percentage").text(cgpa)
        //     $("#education-update").hide();
        // }
    });
    $("#prfl-add-btn").click(function(){
        $("#education-update").show();
});
})

    $(document).ready(function(event){
    $("#skill-edit-btn").click(function(){
        $("#skill-update").show();
    })
    $("#skill-close-btn").click(function(){
        $("#skill-update").hide();
    })
    $("#update-btn-skill").click(function(){
        let skill=$("#skill").val();
        if(skill==""){
            $("#error-notification-skill").show();
        }
        else{
            $("#error-notification-skill").hide();
            event.preventDefault();
        }
    })
    });
$(document).ready(function(){
    $("#experience-add").click(function(){
        $("#experience-update").show();
    })
    $(".edit-experience-btn").click(function(){
        $("#experience-update").show();
    })
    $("#experience-close-btn").click(function(){
        $("#experience-update").hide();
    })
    $("#experience-start-date").focus(function(){
        $(this).attr("type","date")
    })
    $("#experience-end-date").focus(function(){
        $(this).attr("type","date")
    })
    $("#update-btn-experience").click(function(){
        let companyname=$("#experience-com").val();
        let position=$("#experience-position").val();
        let startdate=$("#experience-start-date").val();
        let enddate=$("#experience-end-date").val();
        let detail=$("#experience-details").val();

        if(companyname==""||position==""||startdate==""||enddate==""||detail==""){
           if(companyname=="")
           {
            $("#error-notification-com-name").show();
           }
           if(position=="")
           {
            $("#error-notification-position").show();
           }
           if(startdate=="")
           {
            $("#error-notification-start-date").show();
           }
           if(enddate=="")
           {
            $("#error-notification-end-date").show();
           }
           if(detail=="")
           {
            $("#error-notification-com-detail").show();
           }
        }
    })
    });
    $(document).ready(function(){
        $("#resume-add").click(function(){
            $("#resume-update").show();
        })
        $("#resume-close-btn").click(function(){
            $("#resume-update").hide();
        })
        $("#resume").focus(function(){
            $(this).attr("type","file")
        })
        $("#update-btn-resume").click(function(){
            let resume=$("#resume").val();
            if(resume==""){
                $("#error-notification-resume").show();
            }
            else{
                alert(resume)
            }
        })
        });