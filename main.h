/*

	This file is part of the Malbolge disassembler.
	Copyright (C) 2016 Matthias Lutter

	The Malbolge disassembler is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation, either version 3 of
	the License, or (at your option) any later version.

	The Malbolge disassembler is distributed in the hope that it will be
	useful, but WITHOUT ANY WARRANTY; without even the implied warranty
	of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.

	E-Mail: matthias@lutter.cc



	For more Malbolge stuff, please visit
	<https://lutter.cc/>

*/

#ifndef MAIN_H
#define MAIN_H

#include "avl-2.0.2a/avl.h"

#define HELL_FILE_EXTENSION "hell"
#define MALBOLGE_DEBUG_FILE_EXTENSION "dbg"

typedef struct VMState {
	int a,c,d;
	int memory[59060];
} VMState;


const int DREG_ACCESS_MOVD     = 0x0001; // value might be replaced by destination label (if no RW access at all)
const int DREG_ACCESS_JUMP     = 0x0002; // value might be replaced by destination label (if no RW access at all)
const int DREG_ACCESS_RW       = 0x0004;
const int DREG_REACHED_BY_MOVD = 0x0008; // label required

const int CREG_EXECUTED        = 0x0100; // shall be in CSEG, if not already in DSEG
const int CREG_TRANSLATED      = 0x0200; // that means, we have a direct successor; and it means that the cycle may be important
const int CREG_REACHED_BY_JMP  = 0x0400; // label may be required (or not, if it is just a NOP-Chain, but this is more advanced analysis)
const int CREG_REACHED_WO_JMP  = 0x0800; // that means, we have a direct predecessor

const int FIXED_OFFSET         = 0x8000; // must be at a fixed position


typedef struct MemoryCellInfo {
//	int value; // initial value on entry point
	int access; // flags: DREG_ACCESS_MOVD, DREG_ACCESS_JUMP, DREG_ACCESS_RW, DREG_REACHED_BY_MOVD; CREG_EXECUTED, CREG_TRANSLATED, CREG_REACHED_BY_JMP

	// first successing dreg-cell with interaction, if no movd is performed. movd-successors can be found below.
	struct avl_table* dreg_successors_normal_flow; // use it to build reachability-graph
	struct avl_table* dreg_predecessors_normal_flow; // use it to build reachability-graph

	// in a second step, fix the successor's offset if this cell is modified during execution
	struct avl_table* dreg_movd_destinations;
	struct avl_table* dreg_jmp_destinations;

} MemoryCellInfo;


typedef struct AccessAnalysis {
//	int a,c,d;
//	int n_jump_destinations;
//	int* jump_destinations;
	int a_register_matters;
	int maximal_steps_from_entry_point;
	struct MemoryCellInfo memory[59049];
} AccessAnalysis;

typedef struct UserInput {
	int length;
	int* input;
} UserInput;

const int MALBOLGE_HLT = 0x0001;
const int MALBOLGE_JMP = 0x0002;
const int MALBOLGE_MOV = 0x0004;
const int MALBOLGE_OPR = 0x0008;
const int MALBOLGE_OUT = 0x0010;
const int MALBOLGE_IN  = 0x0020;
const int MALBOLGE_ROT = 0x0040;
const int MALBOLGE_NOP = 0x0080;

typedef struct BreakCondition {
	int maximal_steps; // less or equal zero: don't break
	int on_cseg_outside_analysis; // break if AccessAnalysis is set and a memory cell is firstly used as command (pointed to by cseg). only used for advanced entry point analysis. ; therefore, also break if later CSEG-memory-cells are modified
	int command_mask; // break on malbolge commands (before executing them)
} BreakCondition;



typedef struct ConnectedMemoryCells {
	int fixed_offset;
	int codesection;
	int datasection;
	struct avl_table* cells; // contains their addresses as integer
} ConnectedMemoryCells;



int got_sigint();

void copy_state(struct VMState* dest, const struct VMState* src);

// if interactive is true:  output will be written to terminal; input will be read from terminal and returned by input (if not NULL). break_on: CTRL+C, break_on-Conditions
// if interactive is false: output will be discarded; input will be taken from input (if not NULL), otherwise EOF will be read all the time. will only break on HALT command and break_on-Conditions
// return value: number of steps executed
// VMState start will be modified during execution!
int execute(struct VMState* start, int interactive, struct UserInput* input, struct BreakCondition break_on, int* last_jmp, int* interrupted, struct AccessAnalysis* accesses, int access_analysis_ro);

void copy_access_analysis(struct AccessAnalysis* dest, struct AccessAnalysis* src);
void free_access_analysis(struct AccessAnalysis* access); // only recursive allocations, not the root

#endif

