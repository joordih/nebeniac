import {useState} from 'react'
import {Plus, X} from 'lucide-react'
import {Button} from '@/components/ui/button.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'

export default function DynamicPackageInputs({packages, onChange, label = "Target Packages"}) {
    const [packageInputs, setPackageInputs] = useState(packages || [''])

    const addPackageInput = () => {
        const newInputs = [...packageInputs, '']
        setPackageInputs(newInputs)
        onChange(newInputs)
    }

    const removePackageInput = (index) => {
        if (packageInputs.length > 1) {
            const newInputs = packageInputs.filter((_, i) => i !== index)
            setPackageInputs(newInputs)
            onChange(newInputs)
        }
    }

    const updatePackageInput = (index, value) => {
        const newInputs = [...packageInputs]
        newInputs[index] = value
        setPackageInputs(newInputs)
        onChange(newInputs)
    }

    return (
        <div className="space-y-2">
            <Label>{label}</Label>
            {packageInputs.map((pkg, index) => (
                <div key={index} className="flex items-center space-x-2">
                    <Input
                        placeholder={`e.g., ${index === 0 ? 'net.kerfu.alcachofa' : 'com.example.package'}`}
                        value={pkg}
                        onChange={(e) => updatePackageInput(index, e.target.value)}
                        className="flex-1"
                    />
                    {packageInputs.length > 1 && (
                        <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => removePackageInput(index)}
                            className="text-destructive"
                        >
                            <X className="h-4 w-4"/>
                        </Button>
                    )}
                </div>
            ))}
            <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addPackageInput}
                className="w-full"
            >
                <Plus className="h-4 w-4 mr-2"/>
                Add Package
            </Button>
            <p className="text-sm text-muted-foreground">
                Specify which packages should be encrypted. At least one package is required.
            </p>
        </div>
    )
}
