// document.addEventListener("DOMContentLoaded", function () {
        //     const scriptSelect = document.getElementById("script-select");
        //     const customScriptInput = document.getElementById("custom-script-input");

        //     scriptSelect.addEventListener("change", function () {
        //         if (scriptSelect.value === "other") {
        //             customScriptInput.style.display = "block";
        //             scriptSelect.name = "";  // Hide name to prevent sending
        //         } else {
        //             customScriptInput.style.display = "none";
        //             scriptSelect.name = "script";  // Restore default name
        //         }
        //     });
        // });

        function toggleDetails(button) {
            const details = button.nextElementSibling;
            if (details.style.display === "none") {
                details.style.display = "block";
                button.textContent = "Hide Details";
            } else {
                details.style.display = "none";
                button.textContent = "Show Details";
            }
        }

        function toggleScanForm() {
            document.getElementById("scan").classList.toggle("hidden");
        }

        function toggleAllScripts(selectId, checked) {
            const select = document.getElementById(selectId);
            Array.from(select.options).forEach(option => option.selected = checked);
        }

        function updateSelectedScripts() {
            const badgeContainer = document.getElementById("selected-scripts");
            badgeContainer.innerHTML = "";
        
            document.querySelectorAll(".script-options input[type='checkbox']:checked").forEach(checkbox => {
                const badge = document.createElement("span");
                badge.classList.add("badge");
        
                // Add a specific class based on the checkbox's parent category
                if (checkbox.closest("#service-enum")) {
                    badge.classList.add("badge-category-service-enum");
                } else if (checkbox.closest("#vuln-detection")) {
                    badge.classList.add("badge-category-vuln-detection");
                } else if (checkbox.closest("#brute-force")) {
                    badge.classList.add("badge-category-brute-force");
                } else if (checkbox.closest("#info-gathering")) {
                    badge.classList.add("badge-category-info-gathering");
                } else if (checkbox.closest("#ssl-testing")) {
                    badge.classList.add("badge-category-ssl-testing");
                } else if (checkbox.closest("#malware-detection")) {
                    badge.classList.add("badge-category-malware-detection");
                }
        
                badge.textContent = checkbox.value;
                badgeContainer.appendChild(badge);
            });
        
            const customScript = document.getElementById("custom-script").value.trim();
            if (customScript) {
                const scripts = customScript.split(/[, ]+/); // Split by both coma and space
                scripts.forEach(script => {
                    const badge = document.createElement("span");
                    badge.classList.add("badge", "badge-category-custom-script");
                    badge.textContent = script.trim(); // Trim spaces around each script
                    badgeContainer.appendChild(badge);
                });
            }
        }

        // Attach update function to checkboxes and custom script input
        document.querySelectorAll(".script-options input[type='checkbox']").forEach(checkbox => {
            checkbox.addEventListener("change", updateSelectedScripts);
        });

        document.getElementById("custom-script").addEventListener("input", updateSelectedScripts);


        // Prepare scripts before form submission
        function prepareScripts() {
            const form = document.querySelector("form");
            document.querySelectorAll("input[name='script']").forEach(input => input.remove());

            const selectedScripts = [];
            document.querySelectorAll(".script-options input[type='checkbox']:checked").forEach(checkbox => {
                selectedScripts.push(checkbox.value);
            });

            const customScript = document.getElementById("custom-script").value.trim();
            if (customScript) {
                const scripts = customScript.split(/[, ]+/);
                scripts.forEach(script => {selectedScripts.push(script.trim())});
            }
            
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = "script";
            input.value = selectedScripts.join(',');
            form.appendChild(input);
        }

        function toggleCategory(categoryId) {
            const category = document.getElementById(categoryId);
            if (category.style.display === "none" || !category.style.display) {
                category.style.display = "block";
            } else {
                category.style.display = "none";
            }
        }