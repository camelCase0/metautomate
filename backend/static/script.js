        function toggleCardDetails(header) {
            const content = header.nextElementSibling;
            const arrow = header.querySelector('span');
            
            if (content.style.display === "none" || !content.style.display) {
                content.style.display = "block";
                arrow.textContent = "▲";
            } else {
                content.style.display = "none";
                arrow.textContent = "▼";
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
        async function prepareScripts(event) {
            event.preventDefault();
            runSpinner()
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
            
            const formData = new FormData(form);
            formData.set("script", selectedScripts.join(","));

            try {
                // Submit the form using Fetch API
                const response = await fetch(form.action, {
                    method: form.method,
                    body: formData,
                });
        
                if (!response.ok) {
                    throw new Error(`Error: ${response.statusText}`);
                }
        
                const result = await response.json();
                if (result.scan_id) {
                    // Redirect to the results page using the scan_id
                    window.location.href = `/view-scan/${result.scan_id}`;
                } else {
                    throw new Error("Scan ID not returned.");
                }
            } catch (error) {
                console.error("Scan submission failed:", error);
                alert("Failed to start scan. Please try again.");
                spinner.style.display = "none"; // Hide spinner if there's an error
                spinner_overlay.style.display = "none";
            }
        }

        function toggleCategory(categoryId) {
            const category = document.getElementById(categoryId);
            if (category.style.display === "none" || !category.style.display) {
                category.style.display = "block";
            } else {
                category.style.display = "none";
            }
        }


    const icons = document.querySelectorAll('.icon');
    const progressBar = document.getElementById('progress-bar-inner');
    const statuss = document.getElementById('status');
    const spinner = document.getElementById('spinner');
    const spinner_overlay = document.getElementById("spinner-overlay")

    const phases = [
        { icon: 'globe', text: 'Scanning network...' },
        { icon: 'magnify', text: 'Identifying vulnerabilities...' },
        { icon: 'shield', text: 'Securing assets...' }
    ];

    let currentPhase = 0;

    function updatePhase() {
        // Reset all icons to inactive
        icons.forEach(icon => icon.classList.remove('active'));

        // Activate the current icon
        const activeIcon = document.querySelector(`.${phases[currentPhase].icon}`);
        activeIcon.classList.add('active');

        // Update status text
        statuss.textContent = phases[currentPhase].text;

        // Update progress bar
        progressBar.style.width = `${((currentPhase + 1) / phases.length) * 100}%`;

        // Move to the next phase after a delay
        currentPhase = (currentPhase + 1) % phases.length; // Loop back to the beginning
        setTimeout(updatePhase, 1500); // Adjust delay as needed
    }
    function runSpinner(){
        spinner.style.display = 'block';
        spinner_overlay.style.display = 'block';
        updatePhase();
    }

    async function loadScans() {
        const response = await fetch('/list-scans');
        const data = await response.json();

        const container = document.getElementById('scan-list-container');
        container.innerHTML = '';

        if (data.scans && data.scans.length > 0) {
            data.scans.forEach(scan => {
                const li = document.createElement('li');
                const link = document.createElement('a');
                link.href = `/view-scan/${scan}`;
                link.textContent = scan;
                li.appendChild(link);
                container.appendChild(li);
            });
        } else {
            container.textContent = 'No scans found.';
        }
    }

    loadScans();
