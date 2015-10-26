"use strict";
/**
 * @fileOverview
 * Port of some legacy tests from the old djbec.js module.
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
    
    var assert = chai.assert;

    describe("legacy tests (original fast-djbec.js)", function() {
        describe('signing', function() {
            it('signature round trips', function() {
                this.timeout(this.timeout() * 2);
                var tests = [['msg', '0key'],
                             ['foo', '0baz']];
                for (var i = 0; i < tests.length; i++) {
                    var msg = tests[i][0];
                    var key = tests[i][1];
                    var pk = ns.publicKey(key);
                    var sig = ns.sign(msg, key, pk);
                    assert.ok(ns.verify(sig, msg, pk));
                }
            });
        });
    });

