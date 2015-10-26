/**
 * @fileOverview
 * Ed25519 timing tests using test vectors taken from
 * http://ed25519.cr.yp.to/python/sign.input.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

define([
    "jodid25519/eddsa",
    "chai",
    "asmcrypto",
    "asmcrypto",
], function(ns, chai, asmCrypto) {
    "use strict";

    var assert = chai.assert;

    // Shut up warning messages on random number generation for unit tests.
    asmCrypto.random.skipSystemRNGWarning = true;

    var _td = _td_eddsa;
    asmCrypto.random.seed(new Uint8Array([42]));

    var MIN_TESTS = 50;
    var NUM_TESTS = _td.SIGN_INPUT.length;
    var MAX_TEST_DURATION = 10000; // Duration in milliseconds.

    var arraySum = function(values) {
        return values.reduce(function(a, b) {
            return a + b;
        }, 0);
    };

    var timeIt = function(timings, f) {
        var start = Date.now();
        var r = f();
        var end = Date.now();
        timings.push(end - start);
        return r;
    };

    var timingStatsText = function(timings) {
        var max = Math.max.apply(null, timings);
        var min = Math.min.apply(null, timings);
        var mean = arraySum(timings) / timings.length;
        var esq = arraySum(timings.map(function(x) { return x * x; })) / timings.length;
        var stdev = Math.sqrt(esq - mean*mean);
        var maxpc = ((max - mean) / mean * 100).toFixed(2);
        var minpc = ((mean - min) / mean * 100).toFixed(2);
        var stdevpc = (stdev / mean * 100).toFixed(2);
        return ("(" + timings.length + " tested): " + mean.toFixed(2)
                + " ms, +" + maxpc + "%, -" + minpc + "%, ~" + stdevpc + "%");
    };

    if (window.TEST_TIMING) {
        // Only run this if we're doing timing tests.
        describe("Ed25519 timing tests:", function() {
            it('signing and verification', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    // Fields on each record in vector:
                    // key + pk, pk, msg, sign + msg
                    var vector = _td.SIGN_INPUT[i];
                    var key = atob(vector[0]).slice(0, 32);
                    var msg = atob(vector[2]);
                    var pk = atob(vector[1]);
                    var check = timeIt(timings, function() {
                        var sig = ns.sign(msg, key, pk);
                        return ns.verify(sig, msg, pk);
                    });
                    assert.ok(check, 'verify mismatch on test ' + i);
                }
                console.log('Duration per sign & verify cycle ' + timingStatsText(timings));
            });

            it('signing only', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    // Fields on each record in vector:
                    // key + pk, pk, msg, sign + msg
                    var vector = _td.SIGN_INPUT[i];
                    var key = atob(vector[0]).slice(0, 32);
                    var msg = atob(vector[2]);
                    var pk = atob(vector[1]);
                    timeIt(timings, function() {
                        return ns.sign(msg, key, pk);
                    });
                }
                console.log('Duration per signature ' + timingStatsText(timings));
            });

            it('verify only', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    // Fields on each record in vector:
                    // key + pk, pk, msg, sign + msg
                    var vector = _td.SIGN_INPUT[i];
                    var msg = atob(vector[2]);
                    var pk = atob(vector[1]);
                    var sigCheck = atob(vector[3]).slice(0, 64);
                    var check = timeIt(timings, function() {
                        return ns.verify(sigCheck, msg, pk);
                    });
                    assert.ok(check, 'verify mismatch on test ' + i);
                }
                console.log('Duration per verification ' + timingStatsText(timings));
            });

            it('derive public key', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    // Fields on each record in vector:
                    // key + pk, pk, msg, sign + msg
                    var vector = _td.SIGN_INPUT[i];
                    var key = atob(vector[0]).slice(0, 32);
                    timeIt(timings, function() {
                        return ns.publicKey(key);
                    });
                }
                console.log('Duration per public key computation ' + timingStatsText(timings));
            });

            it('point on curve check', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    // Fields on each record in vector:
                    // key + pk, pk, msg, sign + msg
                    var vector = _td.SIGN_INPUT[i];
                    var pk = atob(vector[1]);
                    timeIt(timings, function() {
                        return ns.isOnCurve(pk);
                    });
                }
                console.log('Duration per point on curve check ' + timingStatsText(timings));
            });

            it('generate private key seed', function() {
                // Extend timeout, this test takes longer.
                this.timeout(1.1 * MAX_TEST_DURATION);
                var timings = [];
                for (var i = 0; arraySum(timings) < MAX_TEST_DURATION
                        && i < NUM_TESTS || i < MIN_TESTS; i++) {
                    timeIt(timings, function() {
                        return ns.generateKeySeed();
                    });
                }
                console.log('Duration per key seed generation ' + timingStatsText(timings));
            });
        });
    }
});
