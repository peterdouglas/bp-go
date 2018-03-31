package bulletproofs

import (
	"math/big"
	"reflect"
	"testing"
)

func TestVectorPCommit(t *testing.T) {
	type args struct {
		value []*big.Int
	}
	tests := []struct {
		name  string
		args  args
		want  ECPoint
		want1 []*big.Int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := VectorPCommit(tt.args.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VectorPCommit() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("VectorPCommit() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestTwoVectorPCommit(t *testing.T) {
	type args struct {
		a []*big.Int
		b []*big.Int
	}
	tests := []struct {
		name string
		args args
		want ECPoint
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TwoVectorPCommit(tt.args.a, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TwoVectorPCommit() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTwoVectorPCommitWithGens(t *testing.T) {
	type args struct {
		G []ECPoint
		H []ECPoint
		a []*big.Int
		b []*big.Int
	}
	tests := []struct {
		name string
		args args
		want ECPoint
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TwoVectorPCommitWithGens(tt.args.G, tt.args.H, tt.args.a, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TwoVectorPCommitWithGens() = %v, want %v", got, tt.want)
			}
		})
	}
}
