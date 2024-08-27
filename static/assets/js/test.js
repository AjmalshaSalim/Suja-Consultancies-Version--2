$(document).ready(function() {
  $("#submitBtn").click(function() {
    var isValid = true;
    var errorMessage = $("#error-message");

    // Iterate through form elements with the [name] attribute
    $("[name]").each(function() {
      var input = $(this);
      var value = input.val();
      var name = input.attr("name");

      // Perform custom validation based on the input's name attribute
      if (name === "name" && value.trim() === "") {
        errorMessage.text("Please enter your name.");
        isValid = false;
      } else if (name === "email" && !isValidEmail(value)) {
        errorMessage.text("Please enter a valid email address.");
        isValid = false;
      }
    });

    if (isValid) {
      errorMessage.text(""); // Clear any previous error messages
      alert("Form submitted successfully!");
      // You can submit the form here if needed
      // $("#myForm").submit();
    }
  });

  // Function to validate email using a regular expression
  function isValidEmail(email) {
    var emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    return emailRegex.test(email);
  }
})

