"use strict";
/**
 * @fileOverview
 * Tests for internal core functions.
 */

/*
 * Copyright (c) 2014 Mega Limited
 * under the MIT License.
 *
 * Authors: Guy K. Kloss
 *
 * You should have received a copy of the license along with this program.
 */

var ns = require('../lib/core');
var utils = require('../lib/utils');
var chai = require('chai');
var sinon = require('sinon');
var crypto = require('crypto');
var _td_dh = require('./dh_test_vectors');

var atob = function(s) { return (new Buffer(s, 'base64').toString('binary')); };
var btoa = function(s) { return (new Buffer(s, 'binary').toString('base64')); };

    var assert = chai.assert;

    var _td = _td_dh;

    // Create/restore Sinon stub/spy/mock sandboxes.
    var sandbox = null;

    beforeEach(function() {
        sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
        sandbox.restore();
    });

    describe("Tests for core functions", function() {
        describe('_generateKey()', function() {
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

            it('general test zeros', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });

            it('general test zeros, curve25519=false', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
                assert.strictEqual(btoa(ns.generateKey(false)), expected);
            });

            it('general test 0xff', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '//////////////////////////////////////////8=';
                assert.strictEqual(btoa(ns.generateKey()), expected);
            });

            it('general test 0xff, curve25519=false', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '//////////////////////////////////////////8=';
                assert.strictEqual(btoa(ns.generateKey(false)), expected);
            });

            it('general test zeros, curve25519=true', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(zeros));
                var expected = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA=';
                assert.strictEqual(btoa(ns.generateKey(true)), expected);
            });

            it('general test 0xff, curve25519=true', function() {
                sandbox.stub(crypto, 'randomBytes', _copy(ffs));
                var expected = '+P///////////////////////////////////////38=';
                assert.strictEqual(btoa(ns.generateKey(true)), expected);
            });
        });
    });

