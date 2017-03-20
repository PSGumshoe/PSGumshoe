Describe "Measure-VectorSimilarity" {

    It "Measures single input same" {
        Measure-PsgVectorSimilarity 1 1 | Should be 1
    }

    It "Measures single input different" {
        Measure-PsgVectorSimilarity 1 0 | Should be 0
    }

    It "Measures comparison to empty array" {
        Measure-PsgVectorSimilarity 1,2,3 @() | Should be 0
    }

    It "Measures identical multiple inputs" {
        Measure-PsgVectorSimilarity @(1..10) @(1..10) | Should be 1
    }

    It "Measures simple numbers" {
        Measure-PsgVectorSimilarity @(1..10) @(3..8) | Should be 0.775
    }

    It "Measures multi-dimensions" {
        $set1 = @( ([PSCustomObject] @{ Name = 'A'; Value = 0 }), ([PSCustomObject] @{ Name = 'B'; Value = 1 }))
        $set2 = @( ([PSCustomObject] @{ Name = 'A'; Value = 0.707 }), ([PSCustomObject] @{ Name = 'B'; Value = 0.707 }))

        Measure-PsgVectorSimilarity $set1 $set2 -KeyProperty Name -ValueProperty Value | Should be 0.707
    }
   
}