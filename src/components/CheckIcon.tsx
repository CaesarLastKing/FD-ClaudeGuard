import {
  Activity,
  Ban,
  Clock,
  CloudUpload,
  EyeOff,
  Globe,
  Lock,
  MapPinOff,
  Power,
  Server,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  LayoutPanelTop,
} from "lucide-react";

interface CheckIconProps {
  name: string;
  size?: number;
}

export function CheckIcon({ name, size = 16 }: CheckIconProps) {
  const props = { size, strokeWidth: 1.75 };
  switch (name) {
    case "proxy":
      return <Server {...props} />;
    case "group":
      return <Lock {...props} />;
    case "geo":
      return <Globe {...props} />;
    case "ipv6":
      return <Ban {...props} />;
    case "dns":
      return <CloudUpload {...props} />;
    case "ban":
      return <ShieldAlert {...props} />;
    case "userLock":
      return <UserCheck {...props} />;
    case "privacy":
      return <EyeOff {...props} />;
    case "startup":
      return <Power {...props} />;
    case "hudIcon":
      return <LayoutPanelTop {...props} />;
    case "clock":
      return <Clock {...props} />;
    case "fw":
      return <Activity {...props} />;
    case "location":
      return <MapPinOff {...props} />;
    default:
      return <ShieldCheck {...props} />;
  }
}
