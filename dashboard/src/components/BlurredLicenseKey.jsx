import {useState} from 'react'
import {Eye, EyeOff} from 'lucide-react'
import {Button} from '@/components/ui/button.jsx'

export default function BlurredLicenseKey({licenseKey, className = ""}) {
    const [isRevealed, setIsRevealed] = useState(false)
    const [isHovered, setIsHovered] = useState(false)

    const toggleReveal = () => {
        setIsRevealed(!isRevealed)
    }

    const shouldShow = isRevealed || isHovered

    return (
        <div className={`flex items-center space-x-2 ${className}`}>
      <span
          className={`font-mono text-sm transition-all duration-200 cursor-pointer select-none ${
              shouldShow
                  ? 'filter-none'
                  : 'filter blur-sm hover:blur-none'
          }`}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={() => setIsHovered(false)}
          onClick={toggleReveal}
          title={shouldShow ? "Click to hide" : "Click or hover to reveal"}
      >
        {licenseKey}
      </span>
            <Button
                variant="ghost"
                size="sm"
                onClick={toggleReveal}
                className="h-6 w-6 p-0"
                title={isRevealed ? "Hide license key" : "Show license key"}
            >
                {isRevealed ? (
                    <EyeOff className="h-3 w-3"/>
                ) : (
                    <Eye className="h-3 w-3"/>
                )}
            </Button>
        </div>
    )
}
