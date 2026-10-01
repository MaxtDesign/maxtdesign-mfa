/*! MaxtDesign MFA admin | GPL-2.0-or-later | copy button + confirm dialog (when the suite script is absent) */
(() => {
	const d = document;
	d.addEventListener('click', (e) => {
		const b = e.target.closest('[data-mdmfa-copy]');
		if (!b || !navigator.clipboard) {
			return;
		}
		const src = d.getElementById(b.dataset.mdmfaCopy);
		const out = b.parentNode.querySelector('.mdmfa-copied');
		navigator.clipboard.writeText(src ? src.textContent : '').then(() => {
			if (out) {
				out.textContent = b.dataset.mdmfaCopied || '';
			}
		});
	});

	// The suite script owns this contract when it is loaded.
	if (!d.querySelector('.mdmfa-standalone') || !window.HTMLDialogElement) {
		return;
	}
	let pass = null;
	d.addEventListener('click', (e) => {
		const b = e.target.closest('[data-md-suite-confirm]');
		if (!b || b === pass) {
			pass = null;
			return;
		}
		e.preventDefault();
		const dlg = d.createElement('dialog');
		const p = d.createElement('p');
		const no = d.createElement('button');
		const yes = d.createElement('button');
		dlg.className = 'mdmfa-dialog';
		p.textContent = b.dataset.mdSuiteConfirm;
		no.type = yes.type = 'button';
		no.className = 'button';
		yes.className = 'button mdmfa-danger';
		no.textContent = d.querySelector('.mdmfa-admin').dataset.mdmfaCancel || 'Cancel';
		yes.textContent = b.dataset.mdSuiteConfirmVerb || 'OK';
		dlg.append(p, no, yes);
		d.body.append(dlg);
		const done = () => {
			if (dlg.isConnected) {
				dlg.remove();
				b.focus();
			}
		};
		no.addEventListener('click', done);
		yes.addEventListener('click', () => {
			done();
			pass = b;
			b.click();
		});
		// Escape closes a modal dialog natively.
		dlg.addEventListener('close', done);
		dlg.showModal();
		no.focus();
	});
})();
