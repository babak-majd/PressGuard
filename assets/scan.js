/* global PressGuardScan */
( function () {
	'use strict';

	var cfg = window.PressGuardScan || {};
	var startBtn = document.getElementById( 'pg-scan-start' );
	var bar = document.getElementById( 'pg-scan-bar' );
	var wrap = document.getElementById( 'pg-scan-progress' );
	var statusEl = document.getElementById( 'pg-scan-status' );
	var summaryEl = document.getElementById( 'pg-scan-summary' );
	var polling = false;

	function post( action ) {
		var body = new URLSearchParams();
		body.set( 'action', action );
		body.set( 'nonce', cfg.nonce );
		return fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		} ).then( function ( r ) { return r.json(); } );
	}

	function fmt( tpl, a, b ) {
		return tpl.replace( '%1$d', a ).replace( '%2$d', b );
	}

	function render( state ) {
		if ( ! state ) { return; }
		var pct = state.percent || 0;
		if ( wrap ) { wrap.style.display = ''; }
		if ( bar ) { bar.style.width = pct + '%'; }
		if ( statusEl ) {
			if ( state.status === 'running' ) {
				statusEl.textContent = cfg.i18n.scanning + ' ' +
					fmt( cfg.i18n.ofFiles, state.scanned || 0, state.total || 0 );
			} else if ( state.status === 'done' ) {
				statusEl.textContent = cfg.i18n.done;
			}
		}
	}

	function loop() {
		if ( polling ) { return; }
		polling = true;
		var tick = function () {
			post( 'pressguard_scan_step' ).then( function ( res ) {
				var state = res && res.data ? res.data : null;
				render( state );
				if ( state && state.status === 'running' ) {
					setTimeout( tick, 600 );
				} else {
					polling = false;
					if ( startBtn ) { startBtn.disabled = false; }
					// Reload once to show the finished report table.
					if ( state && state.status === 'done' ) {
						window.location.reload();
					}
				}
			} ).catch( function () {
				polling = false;
				if ( startBtn ) { startBtn.disabled = false; }
			} );
		};
		tick();
	}

	if ( startBtn ) {
		startBtn.addEventListener( 'click', function () {
			startBtn.disabled = true;
			if ( summaryEl ) { summaryEl.textContent = ''; }
			post( 'pressguard_scan_start' ).then( function ( res ) {
				render( res && res.data ? res.data : null );
				loop();
			} ).catch( function () { startBtn.disabled = false; } );
		} );
	}

	// If a scan is already running (e.g. started elsewhere or via cron), resume
	// the progress display and keep stepping.
	post( 'pressguard_scan_status' ).then( function ( res ) {
		var state = res && res.data ? res.data : null;
		if ( state && state.status === 'running' ) {
			if ( startBtn ) { startBtn.disabled = true; }
			render( state );
			loop();
		}
	} );
} )();
