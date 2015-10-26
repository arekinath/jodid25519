"use strict";
/**
 * @fileOverview
 * API tests for the EdDSA module.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

var ns = require('../lib/eddsa');
var chai = require('chai');
var sinon = require('sinon');
var crypto = require('crypto');

var atob = function(s) { return (new Buffer(s, 'base64').toString('binary')); };
var btoa = function(s) { return (new Buffer(s, 'binary').toString('base64')); };

var _td_eddsa = require('./ecdsa_test_vectors');

    var assert = chai.assert;

    var _td = _td_eddsa;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("API tests", function() {
        describe('verify() function', function() {
            it('signature R not on curve', function() {
                var vector = _td.SIGN_INPUT[42];
                var msg = atob(vector[2]);
                var pk = atob(vector[1]);
                var sigOrig = atob(vector[3]).slice(0, 64);
                var sigMod = String.fromCharCode(0x42) + sigOrig.slice(1, 64);
                assert.throws(function() { ns.verify(sigMod, msg, pk); },
                              'Point is not on curve');
            });

            it('pk not on curve', function() {
                var vector = _td.SIGN_INPUT[42];
                var msg = atob(vector[2]);
                var pk = String.fromCharCode(0x42) + atob(vector[1]).slice(1, 32);
                var sig = atob(vector[3]).slice(0, 64);
                assert.throws(function() { ns.verify(sig, msg, pk); },
                              'Point is not on curve');
            });

            it('good signature', function() {
                var vector = _td.SIGN_INPUT[42];
                var msg = atob(vector[2]);
                var pk = atob(vector[1]);
                var sig = atob(vector[3]).slice(0, 64);
                assert.ok(ns.verify(sig, msg, pk));
            });
        });

        describe('sign() function', function() {
            it('signature call with pk', function() {
                var vector = _td.SIGN_INPUT[42];
                var key = atob(vector[0]).slice(0, 32);
                var msg = atob(vector[2]);
                var pk = atob(vector[1]);
                var sigCheck = atob(vector[3]).slice(0, 64);
                var sig = ns.sign(msg, key, pk);
                assert.strictEqual(sig, sigCheck);
            });

            it('signature call without pk', function() {
                var vector = _td.SIGN_INPUT[42];
                var key = atob(vector[0]).slice(0, 32);
                var msg = atob(vector[2]);
                var sigCheck = atob(vector[3]).slice(0, 64);
                var sig = ns.sign(msg, key);
                assert.strictEqual(sig, sigCheck);
            });

            it('pk not on curve', function() {
                var vector = _td.SIGN_INPUT[42];
                var key = atob(vector[0]).slice(0, 32);
                var msg = atob(vector[2]);
                var pk = String.fromCharCode(0x42) + atob(vector[1]).slice(1, 32);
                var sigCheck = atob(vector[3]).slice(0, 64);
                var sig = ns.sign(msg, key, pk);
                assert.notStrictEqual(sig, sigCheck);
            });
        });

        describe('isOnCurve() function', function() {
            it('for a point on the curve', function() {
                var vector = _td.SIGN_INPUT[42];
                var pk = atob(vector[1]);
                assert.ok(ns.isOnCurve(pk));
            });

            it('point not on curve', function() {
                var vector = _td.SIGN_INPUT[42];
                var pk = String.fromCharCode(0x42) + atob(vector[1]).slice(1, 32);
                assert.notOk(ns.isOnCurve(pk));
            });
        });

        describe('generateKeySeed() function', function() {
            var zeros = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0];
            var ffs = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

            var _copy = function(forced) {
                return (function (len) {
                    return (new Buffer(forced));
                });
            };

            it('generate several different key seeds', function() {
                var compare = '';
                for (var i = 0; i < 5; i++) {
                    var keySeed = ns.generateKeySeed();
                    assert.lengthOf(keySeed, 32);
                    assert.notStrictEqual(keySeed, compare);
                    compare = keySeed;
                }
            });

            it('valid keys with zeros', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
                assert.strictEqual(btoa(ns.generateKeySeed()), expected);
            });

            it('valid keys with 0xff', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '//////////////////////////////////////////8=';
                assert.strictEqual(btoa(ns.generateKeySeed()), expected);
            });
        });

        describe('publicKey() function', function() {
            it('derive public key', function() {
                var vector = _td.SIGN_INPUT[42];
                var key = atob(vector[0]).slice(0, 32);
                var keyCheck = atob(vector[1]);
                assert.strictEqual(ns.publicKey(key), keyCheck);
            });
        });
    });

