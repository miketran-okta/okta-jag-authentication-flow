// Modal functionality
const modal = document.getElementById('stepModal');
const closeBtn = document.getElementsByClassName('close')[0];
const modalTitle = document.getElementById('modalTitle');
const modalBody = document.getElementById('modalBody');
const modalHeader = document.getElementById('modalHeader');

// Add click handlers to hotspots (only for hotspots that exist)
for (let i = 1; i <= 6; i++) {
  const hotspot = document.getElementById('hotspot' + i);
  if (hotspot) {
    hotspot.onclick = function() {
      showStep(i);
    };
  }
}

function showStep(stepNum) {
  const step = stepData[stepNum];
  if (!step) return;
  modalTitle.textContent = step.title;
  modalBody.innerHTML = step.content;

  // Change modal header color based on error state
  if (step.isError) {
    modalHeader.className = 'modal-header error';
  } else {
    modalHeader.className = 'modal-header success';
  }

  modal.style.display = 'block';
}

closeBtn.onclick = function() {
  modal.style.display = 'none';
};

window.onclick = function(event) {
  if (event.target == modal) {
    modal.style.display = 'none';
  }
};

function toggleDetails() {
  const details = document.getElementById('detailedSteps');
  if (details.style.display === 'none') {
    details.style.display = 'block';
  } else {
    details.style.display = 'none';
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('Token copied to clipboard!');
  });
}
