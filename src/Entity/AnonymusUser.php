<?php
namespace Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 * @ORM\Table(
 *     name="AnonymusUsers",
 *     indexes={
 *     @ORM\Index(name="uName", columns={"uName"})
 *     }
 * )
 */
class AnonymusUser
{
    /**
     * @ORM\Id @ORM\Column(type="integer", options={"unsigned": true})
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $uID;

    /**
     * @ORM\OneToMany(targetEntity="\Concrete\Core\Entity\Attribute\Value\UserValue", cascade={"remove"}, mappedBy="user")
     * @ORM\JoinColumn(name="uID", referencedColumnName="uID")
     */
    protected $attributes;

    /**
     * @ORM\Column(type="string", length=64, unique=true)
     */
    protected $uName;

    /**
     * @ORM\Column(type="datetime")
     */
    protected $uDateAdded = null;

    /**
     * @ORM\Column(type="text", nullable=true)
     */
    protected $uLastIP;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uTimezone;

    /**
     * @ORM\Column(type="string", length=32, nullable=true)
     */
    protected $uDefaultLanguage;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    protected $uLastAgent;


    public function __construct()
    {
        $this->uDateAdded = new \DateTime();
    }

    /**
     * @return int
     */
    public function getUserID()
    {
        return $this->uID;
    }

    /**
     * @return string
     */
    public function getUserName()
    {
        return $this->uName;
    }

    /**
     * Gets the date a user was added to the system.
     *
     * @return \DateTime
     */
    public function getUserDateAdded()
    {
        return $this->uDateAdded;
    }

    /**
     * @return string|null
     */
    public function getUserLastIP()
    {
        return $this->uLastIP;
    }

    /**
     * @return string|null
     */
    public function getUserTimezone()
    {
        return $this->uTimezone;
    }

    /**
     * @return string|null
     */
    public function getUserDefaultLanguage()
    {
        return $this->uDefaultLanguage;
    }

    /**
     * @return string|null
     */
    public function getUserLastAgent()
    {
        return $this->uLastAgent;
    }

    /**
     * @param int $uID
     */
    public function setUserID($uID)
    {
        $this->uID = $uID;
    }

    /**
     * @param string $uName
     */
    public function setUserName($uName)
    {
        $this->uName = $uName;
    }

    /**
     * @param \DateTime $uDateAdded
     */
    public function setUserDateAdded($uDateAdded)
    {
        $this->uDateAdded = $uDateAdded;
    }
    
    /**
     * @param string $uLastIP
     */
    public function setUserLastIP($uLastIP)
    {
        $this->uLastIP = $uLastIP;
    }

    /**
     * @param string|null $uTimezone
     */
    public function setUserTimezone($uTimezone)
    {
        $this->uTimezone = $uTimezone;
    }

    /**
     * @param string|null $uDefaultLanguage
     */
    public function setUserDefaultLanguage($uDefaultLanguage)
    {
        $this->uDefaultLanguage = $uDefaultLanguage;
    }


    /**
     * @param string|null $uLastAgent
     */
    public function setUserLastAgent($uLastAgent)
    {
        $this->uLastAgent = $uLastAgent;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->getUserID();
    }

    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return $this->getUserID();
    }
}
