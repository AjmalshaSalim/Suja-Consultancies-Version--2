
    function populateSubcategories() {
        // Get the selected category
        var category = document.getElementById("category").value;

        // Get the subcategory dropdown
        var subcategoryDropdown = document.getElementById("subcategory");

        // Clear existing options
        subcategoryDropdown.innerHTML = "";

        // Add options based on the selected category
        if (category === "Kerala") {
          
            addOption(subcategoryDropdown, "Alappuzha", "Alappuzha");
            addOption(subcategoryDropdown, "Ernakulam", "Ernakulam");
            addOption(subcategoryDropdown, "Idukki", "Idukki");
        } else if (category === "Tamilnadu") {
         
            addOption(subcategoryDropdown, "Ariyalur", "Ariyalur");
            addOption(subcategoryDropdown, "Chengalpattu", "Chengalpattu");
            addOption(subcategoryDropdown, "	Chennai", "	Chennai");
        }
    }

    function addOption(select, value, text) {
        var option = document.createElement("option");
        option.value = value;
        option.text = text;
        select.add(option);
    }

    // Initial population on page load
    populateSubcategories();
